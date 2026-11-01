# Quality Guard sidecar

Standalone sidecar that backs the Grok2API admin page `/quality-guard`.

It talks to the **official admin API** — nothing else:

| | route |
|---|---|
| login | `POST /api/admin/v1/auth/login` |
| nodes / probes / audits | `/api/admin/v1/egress-quality-guard/*` |

Because it authenticates with ordinary admin credentials there is **no
bootstrap.json to wait for and no internal token to provision**. A compose file
only needs an `image:` reference plus credentials.

## Files

| file | role |
|------|------|
| `quality_guard.py` | sidecar process (stdlib only, no host URLs or secrets baked in) |
| `Dockerfile` | standalone image, published to GHCR |
| `QUALITY_GUARD.md` | operator / agent reference (desensitized) |

## Image

Built by `.github/workflows/quality-guard-image.yml` on every change to
`sidecar/`:

```text
ghcr.io/<owner>/<repo>/quality-guard:latest
ghcr.io/<owner>/<repo>/quality-guard:sha-<short>
```

Multi-arch (`linux/amd64`, `linux/arm64`). Standard library only, so the image
carries no pip dependencies and starts in well under a second.

## Compose wiring

Add this next to the existing `grok2api` service. The guard shares the
`grok2api` network so it can resolve the service name:

```yaml
services:
  grok2api:
    image: ghcr.io/chenyme/grok2api:latest
    # ... your existing config ...
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8000/health"]
      interval: 10s
      timeout: 3s
      retries: 12

  quality-guard:
    image: ghcr.io/<owner>/<repo>/quality-guard:latest
    container_name: grok2api-quality-guard
    depends_on:
      grok2api:
        condition: service_started
    environment:
      GROK2API_BASE_URL: http://grok2api:8000
      GROK2API_ADMIN_USERNAME: ${GROK2API_ADMIN_USERNAME:-admin}
      GROK2API_ADMIN_PASSWORD: ${GROK2API_ADMIN_PASSWORD}
      QUALITY_GUARD_MODE: hybrid
      QUALITY_GUARD_SOFT_TPS: "500"
      QUALITY_GUARD_HARD_TPS: "1000"
    restart: unless-stopped
    init: true
    stop_grace_period: 30s
    security_opt:
      - no-new-privileges:true
    # Resource ceiling so a probe burst cannot starve grok2api (see notes).
    mem_limit: 256m
    cpus: 0.5
    pids_limit: 128
```

No volume is required. The guard keeps an optional state cache; point
`QUALITY_GUARD_STATE_DIR` at a writable path if you want it to survive restarts:

```yaml
    volumes:
      - quality_guard_state:/var/lib/grok2api-quality-guard
```

Prefer a secret file over an inline password:

```yaml
    environment:
      GROK2API_ADMIN_PASSWORD_FILE: /run/secrets/grok2api-admin
    secrets:
      - grok2api-admin
```

## Environment variables

### Required

| name | meaning |
|---|---|
| `GROK2API_ADMIN_PASSWORD` | admin password (or use `_FILE`) |

### Connection

| name | default |
|---|---|
| `GROK2API_BASE_URL` | `http://grok2api:8000` |
| `GROK2API_ADMIN_USERNAME` | `admin` |
| `GROK2API_ADMIN_PASSWORD_FILE` | — |
| `QUALITY_GUARD_STATE_DIR` | `/var/lib/grok2api-quality-guard` |

### Detection

| name | default |
|---|---|
| `QUALITY_GUARD_ENABLED` | `true` |
| `QUALITY_GUARD_MODE` | `hybrid` (`active`/`passive`/`hybrid`) |
| `QUALITY_GUARD_MODEL` | `grok-4.6` |
| `QUALITY_GUARD_ACTIVE_INTERVAL_SECONDS` | `1800` |
| `QUALITY_GUARD_PASSIVE_POLL_SECONDS` | `5` |
| `QUALITY_GUARD_SOFT_TPS` | `500` |
| `QUALITY_GUARD_HARD_TPS` | `1000` |
| `QUALITY_GUARD_CONSECUTIVE_SOFT` | `2` |
| `QUALITY_GUARD_CONSECUTIVE_ERRORS` | `2` |
| `QUALITY_GUARD_QUARANTINE_SECONDS` | `300` |
| `QUALITY_GUARD_MIN_HEALTHY_NODES` | `1` |
| `QUALITY_GUARD_NODE_IDS` | empty = auto-discover enabled Build nodes |
| `QUALITY_GUARD_PROMPT` / `QUALITY_GUARD_EXPECTED` | built-in prompt / `QUALITY_OK` |

### Rotation (optional)

| name | default |
|---|---|
| `QUALITY_GUARD_ROTATION_URL` | empty |
| `QUALITY_GUARD_ROTATION_TOKEN` | empty |
| `QUALITY_GUARD_ROTATABLE_NODE_IDS` | empty |

## Config source precedence

`--config-source` selects where thresholds come from:

- `auto` (default) — uses `bootstrap.json` when it exists, otherwise environment
- `env` — environment only
- `bootstrap` — requires the file grok2api writes

Run once to check wiring without starting a detection loop:

```bash
docker run --rm \
  -e GROK2API_ADMIN_USERNAME=admin \
  -e GROK2API_ADMIN_PASSWORD=secret \
  ghcr.io/<owner>/<repo>/quality-guard:latest --check-config
```

```text
configuration is valid (source=env, base=http://grok2api:8000, mode=hybrid, model=grok-4.6)
```

## Resource sizing

The guard is a polling process: one small HTTP request per interval, no browser
and no headless engine. Typical steady state is a few MB of RSS and near-zero
CPU, so `mem_limit: 256m` / `cpus: 0.5` is generous. It performs **one probe per
node per active interval**, not per user request — it will not add load to
`grok2api` under traffic spikes.

Do **not** commit `quality-guard.env`, `bootstrap.json`, admin passwords, or node
proxy URLs.

See `QUALITY_GUARD.md` for detection semantics and recovery behaviour.
