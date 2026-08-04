# Kaya Docker Agent

Docker inventory, metrics and encrypted backup agent for Kaya.

The agent runs on a Docker host, reads the local Docker socket, pushes inventory/metrics back to Kaya over HTTPS, and can execute Kaya Backup Manager jobs for Docker containers.

## Backups

Kaya queues Docker backup and restore jobs. The agent polls Kaya, runs the job on the Docker host, encrypts backup artifacts with AES-256-GCM, writes them to the configured storage path, and reports status back to Kaya.

The backup runner supports local paths and SMB shares directly. For local storage, mount the backup path into the agent container. For SMB storage, configure the host, share/path, username and password in Kaya; no Docker-host mount is required.

By default the agent backs up:

- container metadata and Docker inspect data
- Docker named volume mount paths
- bind mount paths only when explicitly listed in the Kaya backup policy

Bind mounts are not backed up automatically because they can point at large or sensitive host paths. To opt in a bind mount, add its container path to the backup policy, for example:

```text
paths=/config,/data
```

Restore jobs restore backed-up paths into the existing target container. The first version does not recreate missing containers automatically.

## Authentication

Protocol v2 uses separate agent-generated Ed25519 signing and X25519 encryption
keys. Kaya never receives either private key. An administrator provisions Kaya's
dispatch-signing key once, then issues a host-bound bootstrap that expires after
15 minutes and can be used only once.

Set `KAYA_AGENT_BOOTSTRAP_TOKEN` for the first start. After the successful
enrollment, remove that variable and restart the container. Keep the persistent
`KAYA_AGENT_STATE_DIR` volume: it contains the agent identity and private keys,
is created with restrictive permissions, and must not be shared between hosts.

Every subsequent API call is signed with a timestamp and unique request ID.
Backup offers contain no credentials. Credentials, encryption material, and the
short-lived dispatch grant are returned only after an atomic claim, inside a
server-signed X25519/HKDF/AES-GCM envelope.

## Security notes

Access to `/var/run/docker.sock` effectively grants Docker control on the host. Run the agent only on Docker hosts you trust, protect and back up the protocol-v2 state volume, remove the bootstrap after enrollment, and expose Kaya over verified HTTPS.
