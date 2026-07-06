import base64
import hashlib
import io
import json
import os
import re
import socket
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import docker
import requests
import smbclient
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AGENT_PACKAGE_NAME = "kaya-docker-agent"


def resolve_agent_version() -> str:
    # Prefer explicit version injected at image build time.
    env_version = os.getenv("KAYA_AGENT_VERSION") or os.getenv("HOMELAB_AGENT_VERSION")
    if env_version:
        return env_version

    try:
        return version(AGENT_PACKAGE_NAME)
    except PackageNotFoundError:
        return "unknown"


AGENT_VERSION = resolve_agent_version()

AGENT_NAME_HEADER = "Kaya-Docker-Agent"
BACKUP_MAGIC = b"KAYA-BACKUP-v1\n"

KAYA_URL = (os.getenv("KAYA_URL") or os.getenv("HOMELAB_URL") or "").rstrip("/")
AGENT_TOKEN = os.getenv("KAYA_AGENT_TOKEN") or os.getenv("HOMELAB_AGENT_TOKEN") or ""
AGENT_NAME = os.getenv("KAYA_AGENT_NAME") or os.getenv("HOMELAB_AGENT_NAME") or socket.gethostname()
POLL_SECONDS = max(10, int(os.getenv("KAYA_POLL_SECONDS") or os.getenv("HOMELAB_POLL_SECONDS") or "30"))
VERIFY_TLS = (os.getenv("KAYA_VERIFY_TLS") or os.getenv("HOMELAB_VERIFY_TLS") or "true").lower() not in {"0", "false", "no"}
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def auth_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": f"{AGENT_NAME_HEADER}/{AGENT_VERSION}",
    }


def api_url(path: str) -> str:
    if not KAYA_URL:
        raise RuntimeError("KAYA_URL is not set")
    if not AGENT_TOKEN:
        raise RuntimeError("KAYA_AGENT_TOKEN is not set")
    return f"{KAYA_URL}{path}"


def docker_cpu_percent(stats: dict[str, Any]) -> float | None:
    try:
        current = stats.get("cpu_stats") or {}
        previous = stats.get("precpu_stats") or {}

        current_usage = (current.get("cpu_usage") or {}).get("total_usage", 0)
        previous_usage = (previous.get("cpu_usage") or {}).get("total_usage", 0)

        current_system = current.get("system_cpu_usage", 0)
        previous_system = previous.get("system_cpu_usage", 0)

        cpu_delta = current_usage - previous_usage
        system_delta = current_system - previous_system
        online_cpus = current.get("online_cpus") or len(
            (current.get("cpu_usage") or {}).get("percpu_usage") or []
        ) or 1

        if cpu_delta > 0 and system_delta > 0:
            return round((cpu_delta / system_delta) * online_cpus * 100, 2)
    except Exception:
        return None

    return None


def safe_attrs(obj: Any) -> dict[str, Any]:
    try:
        return obj.attrs or {}
    except Exception:
        return {}


def collect_containers(client: docker.DockerClient) -> list[dict[str, Any]]:
    containers = []

    for container in client.containers.list(all=True):
        attrs = safe_attrs(container)
        state = attrs.get("State") or {}
        config = attrs.get("Config") or {}
        labels = config.get("Labels") or {}
        host_config = attrs.get("HostConfig") or {}
        mounts = attrs.get("Mounts") or []

        stats = {}
        if state.get("Running"):
            try:
                stats = container.stats(stream=False) or {}
            except Exception:
                stats = {}

        memory_stats = stats.get("memory_stats") or {}
        memory_used = memory_stats.get("usage")
        memory_total = memory_stats.get("limit")

        containers.append(
            {
                "external_id": container.id,
                "name": container.name,
                "kind": "container",
                "status": state.get("Status") or container.status or "unknown",
                "image": config.get("Image"),
                "cpu_percent": docker_cpu_percent(stats),
                "memory_used": memory_used,
                "memory_total": memory_total,
                "storage_used": attrs.get("SizeRw"),
                "storage_total": None,
                "uptime_seconds": None,
                "tags": labels.get("com.docker.compose.project"),
                "metadata": {
                    "short_id": container.short_id,
                    "created": attrs.get("Created"),
                    "ports": attrs.get("NetworkSettings", {}).get("Ports") or {},
                    "mounts": mounts,
                    "restart_policy": host_config.get("RestartPolicy"),
                    "compose_project": labels.get("com.docker.compose.project"),
                    "compose_service": labels.get("com.docker.compose.service"),
                },
            }
        )

    return containers


def collect_images(client: docker.DockerClient) -> list[dict[str, Any]]:
    items = []

    for image in client.images.list():
        attrs = safe_attrs(image)
        tags = image.tags or []
        items.append(
            {
                "external_id": image.id,
                "name": tags[0] if tags else image.short_id,
                "kind": "image",
                "status": None,
                "size_bytes": attrs.get("Size"),
                "metadata": {
                    "tags": tags,
                    "created": attrs.get("Created"),
                    "architecture": attrs.get("Architecture"),
                    "os": attrs.get("Os"),
                },
            }
        )

    return items


def collect_networks(client: docker.DockerClient) -> list[dict[str, Any]]:
    items = []

    for network in client.networks.list():
        attrs = safe_attrs(network)
        items.append(
            {
                "external_id": network.id,
                "name": network.name,
                "kind": "network",
                "status": attrs.get("Scope"),
                "size_bytes": None,
                "metadata": {
                    "driver": attrs.get("Driver"),
                    "internal": attrs.get("Internal"),
                    "attachable": attrs.get("Attachable"),
                    "ipam": attrs.get("IPAM"),
                },
            }
        )

    return items


def collect_volumes(client: docker.DockerClient) -> list[dict[str, Any]]:
    items = []

    for volume in client.volumes.list():
        attrs = safe_attrs(volume)
        usage = attrs.get("UsageData") or {}
        items.append(
            {
                "external_id": volume.name,
                "name": volume.name,
                "kind": "volume",
                "status": attrs.get("Scope"),
                "size_bytes": usage.get("Size"),
                "metadata": {
                    "driver": attrs.get("Driver"),
                    "mountpoint": attrs.get("Mountpoint"),
                    "labels": attrs.get("Labels") or {},
                },
            }
        )

    return items


def collect_compose_projects(containers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projects: dict[str, dict[str, Any]] = {}

    for container in containers:
        metadata = container.get("metadata") or {}
        project = metadata.get("compose_project")
        if not project:
            continue

        projects.setdefault(
            project,
            {
                "external_id": project,
                "name": project,
                "kind": "compose",
                "status": "active",
                "size_bytes": None,
                "metadata": {"containers": []},
            },
        )

        projects[project]["metadata"]["containers"].append(container["name"])

    return list(projects.values())


def collect_payload() -> dict[str, Any]:
    client = docker.DockerClient(base_url=DOCKER_HOST)
    info = client.info()
    version = client.version()

    containers = collect_containers(client)
    items = []
    items.extend(collect_images(client))
    items.extend(collect_networks(client))
    items.extend(collect_volumes(client))
    items.extend(collect_compose_projects(containers))

    running = [c for c in containers if c.get("status") == "running"]

    return {
        "agent_name": AGENT_NAME,
        "collected_at": utc_now(),
        "platform": "docker-agent",
        "version": f"Agent {AGENT_VERSION} / Docker {version.get('Version')}",
        "host": {
            "name": info.get("Name") or AGENT_NAME,
            "cpu_percent": sum(c.get("cpu_percent") or 0 for c in running),
            "memory_used": sum(c.get("memory_used") or 0 for c in running),
            "memory_total": info.get("MemTotal"),
            "storage_used": None,
            "storage_total": None,
            "metadata": {
                "agent_version": AGENT_VERSION,
                "agent_capabilities": {
                    "docker_backups": True,
                    "backup_restore": True,
                    "backup_storage_targets": ["local", "smb"],
                    "backup_encryption": ["aes-256-gcm"],
                },
                "docker_root_dir": info.get("DockerRootDir"),
                "operating_system": info.get("OperatingSystem"),
                "kernel_version": info.get("KernelVersion"),
                "architecture": info.get("Architecture"),
                "cpus": info.get("NCPU"),
                "server_version": info.get("ServerVersion"),
            },
        },
        "workloads": containers,
        "items": items,
    }


def post_payload(payload: dict[str, Any]) -> None:
    response = requests.post(
        api_url("/infrastructure/vm-docker-manager/api/agent/checkin"),
        headers=auth_headers(),
        data=json.dumps(payload),
        timeout=30,
        verify=VERIFY_TLS,
    )

    if response.status_code >= 400:
        raise RuntimeError(f"Kaya check-in failed: HTTP {response.status_code} {response.text[:500]}")


def fetch_backup_jobs() -> list[dict[str, Any]]:
    response = requests.get(
        api_url("/infrastructure/backup-manager/api/agent/jobs"),
        headers=auth_headers(),
        timeout=30,
        verify=VERIFY_TLS,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"Kaya backup job poll failed: HTTP {response.status_code} {response.text[:500]}")
    payload = response.json()
    jobs = payload.get("jobs") if isinstance(payload, dict) else []
    return jobs if isinstance(jobs, list) else []


def report_backup_job(job_id: int, status: str, **extra: Any) -> None:
    payload = {"status": status}
    payload.update({key: value for key, value in extra.items() if value is not None})
    response = requests.post(
        api_url(f"/infrastructure/backup-manager/api/agent/jobs/{job_id}/status"),
        headers=auth_headers(),
        data=json.dumps(payload),
        timeout=30,
        verify=VERIFY_TLS,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"Kaya backup status update failed: HTTP {response.status_code} {response.text[:500]}")


def derive_backup_key(raw_key: str) -> bytes:
    if not raw_key:
        raise RuntimeError("Backup job did not include an encryption key")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"kaya-agent-backup-v1",
        info=b"docker-backup-artifact",
    ).derive(raw_key.encode("utf-8"))


def encrypt_bytes(data: bytes, raw_key: str) -> bytes:
    nonce = os.urandom(12)
    encrypted = AESGCM(derive_backup_key(raw_key)).encrypt(nonce, data, BACKUP_MAGIC)
    return BACKUP_MAGIC + nonce + encrypted


def decrypt_bytes(data: bytes, raw_key: str) -> bytes:
    if not data.startswith(BACKUP_MAGIC):
        raise RuntimeError("Backup artifact is not a Kaya encrypted backup")
    offset = len(BACKUP_MAGIC)
    nonce = data[offset : offset + 12]
    encrypted = data[offset + 12 :]
    return AESGCM(derive_backup_key(raw_key)).decrypt(nonce, encrypted, BACKUP_MAGIC)


def safe_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return clean[:120] or "container"


def sha_name(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def policy_paths(policy: str | None) -> set[str]:
    if not policy:
        return set()
    found: set[str] = set()
    normalised = policy.replace("\n", ",").replace(";", ",")
    for token in normalised.split(","):
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            key, value = token.split("=", 1)
            if key.strip().lower() not in {"path", "paths", "bind", "binds", "include", "includes"}:
                continue
            token = value.strip()
        if token.startswith("/"):
            found.add(token.rstrip("/") or "/")
    return found


def find_container(client: docker.DockerClient, job: dict[str, Any]):
    external_id = str(job.get("external_id") or "").strip()
    name = str(job.get("container") or "").strip()
    for candidate in [external_id, name]:
        if not candidate:
            continue
        try:
            return client.containers.get(candidate)
        except docker.errors.NotFound:
            continue
    raise RuntimeError(f"Container {name or external_id or 'unknown'} was not found on this Docker host")


def backup_paths_for_container(container, policy: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    attrs = safe_attrs(container)
    mounts = attrs.get("Mounts") or []
    requested_bind_paths = policy_paths(policy)
    paths: list[dict[str, Any]] = []
    logs: list[str] = []
    seen: set[str] = set()

    for mount in mounts:
        destination = str(mount.get("Destination") or "").rstrip("/")
        if not destination or destination in seen:
            continue
        mount_type = mount.get("Type")
        if mount_type == "volume":
            paths.append(
                {
                    "path": destination,
                    "kind": "volume",
                    "name": mount.get("Name"),
                    "source": mount.get("Source"),
                }
            )
            seen.add(destination)
        elif mount_type == "bind" and destination in requested_bind_paths:
            paths.append(
                {
                    "path": destination,
                    "kind": "bind",
                    "source": mount.get("Source"),
                }
            )
            seen.add(destination)

    skipped_binds = [
        str(mount.get("Destination"))
        for mount in mounts
        if mount.get("Type") == "bind" and str(mount.get("Destination") or "").rstrip("/") not in seen
    ]
    if skipped_binds:
        logs.append(
            "Skipped bind mounts not explicitly listed in the backup policy: "
            + ", ".join(sorted(path for path in skipped_binds if path))
        )

    return paths, logs


def add_bytes_to_tar(bundle: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    bundle.addfile(info, io.BytesIO(data))


def read_container_archive(container, path: str) -> tuple[bytes, dict[str, Any]]:
    chunks, stat = container.get_archive(path)
    data = b"".join(chunks)
    return data, stat or {}


def smb_unc_path(target: dict[str, Any], *children: str) -> str:
    host = str(target.get("remote_host") or "").strip().strip("\\/")
    share_path = str(target.get("remote_share") or "").strip().strip("\\/")
    if not host:
        raise RuntimeError("SMB backup target is missing remote_host")
    if not share_path:
        raise RuntimeError("SMB backup target is missing remote_share")
    parts = [part for part in share_path.replace("\\", "/").split("/") if part]
    share = parts[0]
    path_parts = parts[1:]
    for child in children:
        path_parts.extend(part for part in str(child).replace("\\", "/").split("/") if part)
    suffix = ("\\" + "\\".join(path_parts)) if path_parts else ""
    return f"\\\\{host}\\{share}{suffix}"


def smb_register(target: dict[str, Any]) -> str:
    host = str(target.get("remote_host") or "").strip()
    username = str(target.get("remote_username") or "").strip() or None
    password = target.get("remote_password") or None
    smbclient.register_session(host, username=username, password=password)
    return host


def smb_makedirs(target: dict[str, Any], *children: str) -> None:
    host = smb_register(target)
    try:
        current_children: list[str] = []
        for child in children:
            for part in str(child).replace("\\", "/").split("/"):
                if not part:
                    continue
                current_children.append(part)
                path = smb_unc_path(target, *current_children)
                try:
                    smbclient.mkdir(path)
                except Exception:
                    pass
    finally:
        try:
            smbclient.delete_session(host)
        except Exception:
            pass


def write_backup_artifact(target: dict[str, Any], container_name: str, filename: str, data: bytes) -> tuple[str, int]:
    storage_type = str(target.get("type") or "local").lower()
    container_dir = safe_name(container_name)
    if storage_type == "smb":
        smb_makedirs(target, "docker", container_dir)
        host = smb_register(target)
        artifact = smb_unc_path(target, "docker", container_dir, filename)
        try:
            with smbclient.open_file(artifact, mode="wb") as handle:
                handle.write(data)
            size = smbclient.stat(artifact).st_size
        finally:
            try:
                smbclient.delete_session(host)
            except Exception:
                pass
        return artifact, int(size)

    if storage_type != "local":
        raise RuntimeError(f"Agent-side backups do not yet support {storage_type.upper()} storage directly")

    storage_path = Path(str(target.get("path") or "/mnt/backups"))
    storage_path.mkdir(parents=True, exist_ok=True)
    if not storage_path.is_dir():
        raise RuntimeError(f"Backup target {storage_path} is not a directory")
    artifact_dir = storage_path / "docker" / container_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact = artifact_dir / filename
    artifact.write_bytes(data)
    return str(artifact), artifact.stat().st_size


def read_backup_artifact(target: dict[str, Any], artifact_path: str) -> bytes:
    storage_type = str(target.get("type") or "local").lower()
    if artifact_path.startswith("\\\\") or storage_type == "smb":
        host = smb_register(target)
        try:
            with smbclient.open_file(artifact_path, mode="rb") as handle:
                return handle.read()
        finally:
            try:
                smbclient.delete_session(host)
            except Exception:
                pass
    return Path(artifact_path).read_bytes()


def create_backup_bundle(job: dict[str, Any], container) -> tuple[bytes, dict[str, Any], str]:
    attrs = safe_attrs(container)
    config = attrs.get("Config") or {}
    paths, log_lines = backup_paths_for_container(container, job.get("policy"))
    manifest = {
        "format": "kaya-docker-backup-v1",
        "created_at": utc_now(),
        "agent_version": AGENT_VERSION,
        "container": {
            "id": container.id,
            "name": container.name,
            "image": config.get("Image"),
            "labels": config.get("Labels") or {},
            "attrs": attrs,
        },
        "paths": [],
    }

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        for item in paths:
            try:
                archive_bytes, stat = read_container_archive(container, item["path"])
            except Exception as exc:
                raise RuntimeError(f"Could not read {item['path']} from {container.name}: {exc}") from exc

            archive_name = f"archives/{sha_name(item['path'])}.tar"
            add_bytes_to_tar(bundle, archive_name, archive_bytes)
            manifest["paths"].append(
                {
                    **item,
                    "archive": archive_name,
                    "stat": stat,
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                    "size_bytes": len(archive_bytes),
                }
            )

        add_bytes_to_tar(bundle, "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))

    if not paths:
        log_lines.append("No Docker named volumes or opted-in bind mounts were found; saved container metadata only.")
    return stream.getvalue(), manifest, "\n".join(log_lines)


def run_backup_job(client: docker.DockerClient, job: dict[str, Any]) -> dict[str, Any]:
    container = find_container(client, job)
    bundle, manifest, log = create_backup_bundle(job, container)
    encrypted = encrypt_bytes(bundle, (job.get("encryption") or {}).get("key") or "")
    filename = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-job-{job['id']}.kaya-backup"
    artifact_path, size_bytes = write_backup_artifact(job.get("target") or {}, container.name, filename, encrypted)

    return {
        "artifact_path": artifact_path,
        "size_bytes": size_bytes,
        "log": log,
        "metadata": {
            "agent_version": AGENT_VERSION,
            "container": container.name,
            "format": manifest["format"],
            "path_count": len(manifest["paths"]),
            "paths": [item["path"] for item in manifest["paths"]],
        },
    }


def safe_extract_tar(tar: tarfile.TarFile, target: Path) -> None:
    target = target.resolve()
    for member in tar.getmembers():
        destination = (target / member.name).resolve()
        try:
            destination.relative_to(target)
        except ValueError:
            raise RuntimeError(f"Refusing unsafe backup member path: {member.name}")
        tar.extract(member, target)


def decrypt_bundle_to_temp(target: dict[str, Any], artifact_path: str, raw_key: str, temp_dir: Path) -> Path:
    bundle_bytes = decrypt_bytes(read_backup_artifact(target, artifact_path), raw_key)
    bundle_path = temp_dir / "bundle.tar.gz"
    bundle_path.write_bytes(bundle_bytes)
    extract_dir = temp_dir / "bundle"
    extract_dir.mkdir()
    with tarfile.open(bundle_path, "r:gz") as tar:
        safe_extract_tar(tar, extract_dir)
    return extract_dir


def load_manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("Backup artifact is missing manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "kaya-docker-backup-v1":
        raise RuntimeError("Backup artifact format is not supported by this agent")
    return manifest


def run_restore_job(client: docker.DockerClient, job: dict[str, Any]) -> dict[str, Any]:
    source_artifact = str(job.get("source_artifact") or "").strip()
    if not source_artifact:
        raise RuntimeError("Restore job did not include a source artifact")

    container = find_container(client, job)
    with tempfile.TemporaryDirectory(prefix="kaya-restore-") as temp:
        bundle_dir = decrypt_bundle_to_temp(
            job.get("target") or {},
            source_artifact,
            (job.get("encryption") or {}).get("key") or "",
            Path(temp),
        )
        manifest = load_manifest(bundle_dir)
        restored_paths = []
        for item in manifest.get("paths") or []:
            path = str(item.get("path") or "")
            archive_name = str(item.get("archive") or "")
            if not path.startswith("/") or not archive_name.startswith("archives/"):
                raise RuntimeError(f"Backup manifest contains an unsafe restore path: {path}")
            archive_path = bundle_dir / archive_name
            archive_bytes = archive_path.read_bytes()
            expected_sha = item.get("sha256")
            if expected_sha and hashlib.sha256(archive_bytes).hexdigest() != expected_sha:
                raise RuntimeError(f"Archive checksum failed for {path}")
            if not container.put_archive("/", archive_bytes):
                raise RuntimeError(f"Docker refused restore archive for {path}")
            restored_paths.append(path)

    return {
        "artifact_path": source_artifact,
        "size_bytes": int(job.get("source_size_bytes") or 0) or None,
        "log": "Restored paths: " + (", ".join(restored_paths) if restored_paths else "metadata only"),
        "metadata": {
            "agent_version": AGENT_VERSION,
            "container": container.name,
            "restored_paths": restored_paths,
        },
    }


def process_backup_job(client: docker.DockerClient, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    operation = str(job.get("operation") or "").lower()
    report_backup_job(job_id, "running", log=f"Agent {AGENT_VERSION} started {operation} job")
    try:
        if operation == "backup":
            result = run_backup_job(client, job)
        elif operation == "restore":
            result = run_restore_job(client, job)
        else:
            raise RuntimeError(f"Unsupported backup operation: {operation}")
        report_backup_job(job_id, "successful", **result)
        print(f"{utc_now()} {operation} job #{job_id} successful")
    except Exception as exc:
        message = str(exc)
        report_backup_job(job_id, "failed", error=message, log=message)
        print(f"{utc_now()} {operation} job #{job_id} failed: {message}")


def process_backup_jobs(client: docker.DockerClient) -> None:
    jobs = fetch_backup_jobs()
    for job in jobs:
        process_backup_job(client, job)


def main() -> None:
    print(f"Kaya Docker Agent {AGENT_VERSION} starting as {AGENT_NAME}")
    print(f"Kaya URL: {KAYA_URL}")
    print(f"Docker host: {DOCKER_HOST}")
    print(f"Poll interval: {POLL_SECONDS}s")

    while True:
        try:
            client = docker.DockerClient(base_url=DOCKER_HOST)
            payload = collect_payload()
            post_payload(payload)
            print(f"{utc_now()} check-in successful: {len(payload['workloads'])} workloads")
            process_backup_jobs(client)
        except Exception as exc:
            print(f"{utc_now()} agent loop failed: {exc}")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
