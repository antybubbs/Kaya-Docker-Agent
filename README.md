# Kaya Docker Agent

Read-only Docker inventory and metrics agent for HomeLab.

The agent runs on a Docker host, reads the local Docker socket, and pushes inventory/metrics back to Kaya over HTTPS.

## Authentication

Kaya v0.18.0 and later stores Docker agent tokens as SHA-256 hashes. When
creating or regenerating an agent token, copy the original plaintext token shown
by HomeLab and set it as `HOMELAB_AGENT_TOKEN`. The plaintext token is shown only
once and cannot be recovered from the stored hash.

The agent sends that original token to the check-in endpoint as:

```http
Authorization: Bearer <token>
```

Do not configure the agent with the SHA-256 hash.
