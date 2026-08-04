from __future__ import annotations

import base64
import calendar
import hashlib
import json
import os
import stat
import time
import re
import unicodedata
import uuid
from pathlib import Path
from urllib.parse import quote_from_bytes, unquote_to_bytes

import requests
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("invalid unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_query(raw_query: str) -> str:
    if not raw_query:
        return ""
    pairs = []
    for item in raw_query.split("&"):
        if not item:
            raise ValueError("blank query pair")
        key, separator, value = item.partition("=")
        if not key:
            raise ValueError("blank query key")
        pairs.append((_canonical_component(key, False), _canonical_component(value if separator else "", False)))
    encoded = sorted(pairs)
    return "&".join(f"{key}={value}" for key, value in encoded)


def _canonical_component(value: str, path_segment: bool) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value) or "\\" in value or "\x00" in value:
        raise ValueError("invalid encoding")
    raw = unquote_to_bytes(value)
    if b"\\" in raw or b"\x00" in raw or (path_segment and b"/" in raw):
        raise ValueError("invalid delimiter")
    normalized = unicodedata.normalize("NFC", raw.decode("utf-8")).encode("utf-8")
    return quote_from_bytes(normalized, safe="~-._")


def canonical_path(raw_path: str) -> str:
    if not raw_path.startswith("/") or len(raw_path.encode("ascii")) > 2048:
        raise ValueError("invalid path")
    segments = raw_path.split("/")
    if any(segment == "" for segment in segments[1:-1]):
        raise ValueError("empty segment")
    encoded = []
    for segment in segments[1:]:
        value = _canonical_component(segment, True)
        if unquote_to_bytes(value).decode("utf-8") in {".", ".."}:
            raise ValueError("dot segment")
        encoded.append(value)
    return "/" + "/".join(encoded)


def canonical_request(method: str, path: str, raw_query: str, agent_id: str, key_id: str, request_id: str, timestamp: int, body: bytes) -> bytes:
    lines = ("KAYA-AGENT-V2", method.upper(), canonical_path(path), canonical_query(raw_query), agent_id, key_id, request_id, str(timestamp), hashlib.sha256(body).hexdigest())
    return "\n".join(lines).encode()


class ProtocolV2Client:
    def __init__(self, base_url: str, state_dir: Path, verify_tls: bool = True, bootstrap_token: str = "", user_agent: str = "Kaya-Docker-Agent"):
        self.base_url = base_url.rstrip("/")
        self.state_dir = state_dir
        self.verify_tls = verify_tls
        self.bootstrap_token = bootstrap_token
        self.user_agent = user_agent
        self.state_path = state_dir / "protocol-v2.json"
        self.state = self._load_or_enroll()

    def _new_keys(self) -> tuple[Ed25519PrivateKey, X25519PrivateKey]:
        return Ed25519PrivateKey.generate(), X25519PrivateKey.generate()

    @staticmethod
    def _raw_private(key) -> str:
        return b64u(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))

    @staticmethod
    def _raw_public(key) -> str:
        return b64u(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def _load_or_enroll(self) -> dict:
        if self.state_path.exists():
            mode = stat.S_IMODE(self.state_path.stat().st_mode)
            if os.name != "nt" and mode & 0o077:
                raise RuntimeError("Protocol-v2 state file permissions must be 0600")
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        if not self.bootstrap_token:
            raise RuntimeError("KAYA_AGENT_BOOTSTRAP_TOKEN is required for first enrollment")
        signing, envelope = self._new_keys()
        response = requests.post(
            f"{self.base_url}/api/agent/v2/register",
            json={"bootstrap_token": self.bootstrap_token, "signing_public_key": self._raw_public(signing), "envelope_public_key": self._raw_public(envelope)},
            headers={"User-Agent": self.user_agent}, timeout=30, verify=self.verify_tls,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Protocol-v2 enrollment failed: HTTP {response.status_code}")
        registered = response.json()
        state = {
            "agent_id": registered["agent_id"], "key_id": registered["key_id"],
            "signing_private_key": self._raw_private(signing), "envelope_private_key": self._raw_private(envelope),
            "server_signing_keys": {item["key_id"]: item["public_key"] for item in registered["server_signing_keys"]},
        }
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
        return state

    def request(self, method: str, path: str, payload: dict | None = None, raw_query: str = "") -> requests.Response:
        body = canonical_json(payload) if payload is not None else b""
        request_id, timestamp = str(uuid.uuid4()), int(time.time())
        signed = canonical_request(method, path, raw_query, self.state["agent_id"], self.state["key_id"], request_id, timestamp, body)
        private = Ed25519PrivateKey.from_private_bytes(b64u_decode(self.state["signing_private_key"]))
        headers = {
            "Content-Type": "application/json", "User-Agent": self.user_agent, "X-Kaya-Agent-Protocol": "2",
            "X-Kaya-Agent-ID": self.state["agent_id"], "X-Kaya-Agent-Key-ID": self.state["key_id"],
            "X-Kaya-Agent-Timestamp": str(timestamp), "X-Kaya-Agent-Request-ID": request_id,
            "X-Kaya-Agent-Signature": b64u(private.sign(signed)),
        }
        url = f"{self.base_url}{path}" + (f"?{raw_query}" if raw_query else "")
        return requests.request(method, url, headers=headers, data=body, timeout=30, verify=self.verify_tls)

    def rotate_keys(self, bootstrap_token: str) -> None:
        if not bootstrap_token:
            raise RuntimeError("A fresh host-bound bootstrap is required for rotation")
        signing, envelope = self._new_keys()
        response = self.request("POST", "/api/agent/v2/rotate", {"bootstrap_token": bootstrap_token, "signing_public_key": self._raw_public(signing), "envelope_public_key": self._raw_public(envelope)})
        if response.status_code >= 400:
            raise RuntimeError(f"Protocol-v2 key rotation failed: HTTP {response.status_code}")
        updated = dict(self.state)
        updated.update({"key_id": response.json()["key_id"], "signing_private_key": self._raw_private(signing), "envelope_private_key": self._raw_private(envelope)})
        temporary = self.state_path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(updated, handle, sort_keys=True)
        os.replace(temporary, self.state_path)
        self.state = updated

    def open_envelope(self, envelope: dict, expected_dispatch_id: str, expected_claim_id: str) -> dict:
        if envelope.get("version") != 2 or envelope.get("algorithm") != "X25519-HKDF-SHA256+A256GCM":
            raise RuntimeError("Unsupported dispatch envelope")
        signature = envelope.get("server_signature")
        unsigned = dict(envelope)
        unsigned.pop("server_signature", None)
        public_text = self.state["server_signing_keys"].get(envelope.get("server_signing_key_id"))
        if not public_text:
            raise RuntimeError("Dispatch used an unpinned server signing key")
        try:
            Ed25519PublicKey.from_public_bytes(b64u_decode(public_text)).verify(b64u_decode(signature), canonical_json(unsigned))
            aad_bytes = b64u_decode(envelope["aad"])
            aad = json.loads(aad_bytes)
            if aad["agent_id"] != self.state["agent_id"] or aad["dispatch_id"] != expected_dispatch_id or aad["claim_id"] != expected_claim_id:
                raise ValueError("dispatch context mismatch")
            expires = calendar.timegm(time.strptime(aad["expires_at"], "%Y-%m-%dT%H:%M:%SZ"))
            if expires < time.time():
                raise ValueError("dispatch envelope expired")
            private = X25519PrivateKey.from_private_bytes(b64u_decode(self.state["envelope_private_key"]))
            shared = private.exchange(X25519PublicKey.from_public_bytes(b64u_decode(envelope["ephemeral_public_key"])))
            fields = ["kaya:backup-agent:envelope:v2", aad["agent_id"], aad["agent_encryption_key_id"], aad["host_id"], aad["job_id"], aad["dispatch_id"], aad["claim_id"], aad["operation"], aad["expires_at"], aad["manifest_sha256"]]
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64u_decode(envelope["hkdf_salt"]), info="\n".join(fields).encode()).derive(shared)
            plaintext = AESGCM(key).decrypt(b64u_decode(envelope["nonce"]), b64u_decode(envelope["ciphertext"]), aad_bytes)
            result = json.loads(plaintext)
            if hashlib.sha256(canonical_json(result["manifest"])).hexdigest() != aad["manifest_sha256"]:
                raise ValueError("manifest digest mismatch")
            return result
        except (InvalidSignature, InvalidTag, KeyError, ValueError, TypeError) as exc:
            raise RuntimeError("Dispatch envelope authentication failed") from exc
