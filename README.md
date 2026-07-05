# Kaya Docker Agent

Docker inventory, metrics and encrypted backup agent for Kaya.

The agent runs on a Docker host, reads the local Docker socket, pushes inventory/metrics back to Kaya over HTTPS, and can execute Kaya Backup Manager jobs for Docker containers.

## Backups

Kaya queues Docker backup and restore jobs. The agent polls Kaya, runs the job on the Docker host, encrypts backup artifacts with AES-256-GCM, writes them to the configured storage path, and reports status back to Kaya.

The first backup runner supports local or mounted storage paths, for example `/mnt/backups`. If you use SMB, NFS, SFTP or another remote target, mount it on the Docker host and expose the same path to the agent container.

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

Kaya stores Docker agent tokens as SHA-256 hashes. When
creating or regenerating an agent token, copy the original plaintext token shown
by Kaya and set it as `KAYA_AGENT_TOKEN`. The plaintext token is shown only
once and cannot be recovered from the stored hash.

The agent sends that original token to the check-in endpoint as:

```http
Authorization: Bearer <token>
```

Do not configure the agent with the SHA-256 hash.

`HOMELAB_*` environment variables are still accepted for older installs, but new installs should use `KAYA_*`.

## Security notes

Access to `/var/run/docker.sock` effectively grants Docker control on the host. Run the agent only on Docker hosts you trust, protect the agent token, and expose Kaya over HTTPS.
