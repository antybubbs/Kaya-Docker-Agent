import json
import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import protocol_v2
from protocol_v2 import ProtocolV2Client, b64u, b64u_decode, canonical_json, canonical_query, canonical_request


def test_shared_request_vector():
    vector = json.loads((Path(__file__).parent / "protocol-v2-request-vector.json").read_text(encoding="utf-8"))
    body = b64u_decode(vector["body_base64"])
    canonical = canonical_request(vector["method"], vector["path"], vector["raw_query"], vector["agent_id"], vector["key_id"], vector["request_id"], vector["timestamp"], body)
    assert canonical.decode() == vector["canonical_request"]
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["agent_ed25519_private_seed_hex"]))
    assert b64u(private.sign(canonical)) == vector["signature"]
    assert canonical_query("tag=%c3%a9") == "tag=%C3%A9"


def test_enrolment_generates_separate_private_keys_and_persists_restrictively(tmp_path, monkeypatch):
    signing_public = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    response = SimpleNamespace(status_code=200, json=lambda: {"agent_id": "synthetic-agent", "key_id": "synthetic-key", "server_signing_keys": [{"key_id": "server-key", "public_key": b64u(signing_public)}]})
    monkeypatch.setattr(protocol_v2.requests, "post", lambda *args, **kwargs: response)
    client = ProtocolV2Client("https://kaya.example.invalid", tmp_path, bootstrap_token="synthetic-bootstrap")
    assert client.state["signing_private_key"] != client.state["envelope_private_key"]
    assert client.state_path.exists()
    if protocol_v2.os.name != "nt":
        assert client.state_path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(protocol_v2.requests, "post", lambda *args, **kwargs: pytest.fail("bootstrap was reused"))
    assert ProtocolV2Client("https://kaya.example.invalid", tmp_path).state["agent_id"] == "synthetic-agent"


def make_envelope(expiry_offset=600):
    agent_private, ephemeral, server_private = X25519PrivateKey.generate(), X25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expiry_offset))
    manifest = {"job_id": "9", "operation": "backup", "policy": "full", "target_type": "local", "workload_ref": "container"}
    aad = {"agent_encryption_key_id": "agent", "agent_id": "agent", "claim_id": "claim", "dispatch_id": "dispatch", "expires_at": expires, "host_id": "3", "job_id": "9", "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(), "operation": "backup", "protocol_version": 2}
    aad_bytes = canonical_json(aad)
    salt, nonce = bytes(range(32)), bytes(range(12))
    shared = ephemeral.exchange(agent_private.public_key())
    fields = ["kaya:backup-agent:envelope:v2", aad["agent_id"], aad["agent_encryption_key_id"], aad["host_id"], aad["job_id"], aad["dispatch_id"], aad["claim_id"], aad["operation"], aad["expires_at"], aad["manifest_sha256"]]
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info="\n".join(fields).encode()).derive(shared)
    plaintext = {"dispatch_grant": "fake", "manifest": manifest, "target": {"type": "local"}, "encryption": {"mode": "agent-aes-256-gcm", "data_key": "fake"}}
    envelope = {"aad": b64u(aad_bytes), "algorithm": "X25519-HKDF-SHA256+A256GCM", "ciphertext": b64u(AESGCM(key).encrypt(nonce, canonical_json(plaintext), aad_bytes)), "ephemeral_public_key": b64u(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), "hkdf_salt": b64u(salt), "nonce": b64u(nonce), "server_signing_key_id": "server", "version": 2}
    envelope["server_signature"] = b64u(server_private.sign(canonical_json(envelope)))
    client = ProtocolV2Client.__new__(ProtocolV2Client)
    client.state = {"agent_id": "agent", "envelope_private_key": b64u(agent_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())), "server_signing_keys": {"server": b64u(server_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}}
    return client, envelope, plaintext


def test_envelope_rejects_ciphertext_aad_signature_expiry_and_wrong_binding():
    client, envelope, plaintext = make_envelope()
    assert client.open_envelope(envelope, "dispatch", "claim") == plaintext
    for field in ("ciphertext", "aad", "server_signature"):
        changed = dict(envelope)
        raw = bytearray(b64u_decode(changed[field]))
        raw[0] ^= 1
        changed[field] = b64u(bytes(raw))
        with pytest.raises(RuntimeError):
            client.open_envelope(changed, "dispatch", "claim")
    with pytest.raises(RuntimeError):
        client.open_envelope(envelope, "wrong-dispatch", "claim")
    expired_client, expired, _ = make_envelope(expiry_offset=-301)
    with pytest.raises(RuntimeError):
        expired_client.open_envelope(expired, "dispatch", "claim")
