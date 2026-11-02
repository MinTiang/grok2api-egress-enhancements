# Quality Guard sidecar

Drop-in image for the official grok2api quality guard, published to GHCR so a
compose file only needs an `image:` reference instead of building next to an
upstream checkout.

## Same contract as upstream

The runtime contract is unchanged from
`chenyme/grok2api:tools/egress-quality-guard`:

| aspect | behaviour |
|---|---|
| config source | `/var/lib/grok2api-quality-guard/bootstrap.json`, written by grok2api |
| auth | scoped internal token from that file |
| API | `/api/internal/v1/quality-guard/*` |
| environment | `GROK2API_BASE_URL` only |

There are no extra credentials to supply: the shared `quality_guard_state`
volume carries the bootstrap file and the token.

## Version pairing

The guard adapts to whichever generation of the main service it is paired
with, because the internal token is scoped to a fixed route allowlist:

| main service | guard behaviour |
|---|---|
| has `/egress-leases/*` | account-bound proxy nodes are quarantined per account lease, pinned to the same account on recovery |
| lacks `/egress-leases/*` | lease routes answer 403; degrade is handled per account through the admin API (needs `GROK2API_ADMIN_*`), and windowed escalation to the node |
| either | account-bound proxy nodes are **never** disabled node-wide |

Run the preflight before switching images:

```bash
docker compose run --rm egress-quality-guard quality-guard-preflight
```

It reports base URL, mode, node counts, which routes answer, whether the lease
API is present, and whether the current `runtime-config.json` validates — the
three things that silently misconfigure a guard.

## Files

| file | role |
|------|------|
| `quality_guard.py` | sidecar process (stdlib only) |
| `quality_guard_test.py` | classifier + contract tests, run in CI before the image builds |
| `preflight.py` | route/capability check against a live grok2api |
| `Dockerfile` | standalone image, published to GHCR |
| `QUALITY_GUARD.md` | operator / agent reference (desensitized) |

## Image

Built by `.github/workflows/quality-guard-image.yml` on every change to
`sidecar/`:

```text
ghcr.io/<owner>/<repo>/quality-guard:latest
ghcr.io/<owner>/<repo>/quality-guard:sha-<short>
ghcr.io/<owner>/<repo>/quality-guard:vX.Y.Z
```

Multi-arch (`linux/amd64`, `linux/arm64`). Standard library only, so the image
carries no pip dependencies and starts instantly.

## Compose

Identical to the upstream service block, with `build:` replaced by `image:`:

```yaml
services:
  grok2api:
    image: ghcr.io/chenyme/grok2api:latest
    environment:
      GROK2API_QUALITY_GUARD_DIR: /var/lib/grok2api-quality-guard
    volumes:
      - quality_guard_state:/var/lib/grok2api-quality-guard

  egress-quality-guard:
    container_name: grok2api-egress-quality-guard
    image: ghcr.io/<owner>/<repo>/quality-guard:latest
    profiles: ["quality-guard"]
    environment:
      GROK2API_BASE_URL: ${GROK2API_BASE_URL:-http://grok2api:8000}
    depends_on:
      grok2api:
        condition: service_healthy
    volumes:
      - quality_guard_state:/var/lib/grok2api-quality-guard
    restart: "on-failure:5"
    init: true
    stop_grace_period: 30s
    security_opt:
      - no-new-privileges:true

volumes:
  quality_guard_state:
```

Start it exactly as upstream documents:

```bash
docker compose --profile quality-guard up -d
```

Enable detection on the grok2api side in `config.yaml`:

```yaml
qualityGuard:
  enabled: true
  mode: hybrid
```

The guard stays idle until `bootstrap.json` appears, which happens once
grok2api starts with `qualityGuard.enabled: true`. That ordering is why
`depends_on` only needs `service_healthy`, not a file wait.

## Verify before wiring it in

```bash
# no bootstrap yet -> clean, explicit error (exit 2)
docker run --rm ghcr.io/<owner>/<repo>/quality-guard:latest

# with a bootstrap present -> validates and prints the resolved config
docker run --rm \
  -v quality_guard_state:/var/lib/grok2api-quality-guard \
  ghcr.io/<owner>/<repo>/quality-guard:latest --check-config
```

```text
configuration is valid
```

To exercise one detection cycle without daemonizing:

```bash
docker run --rm \
  -e GROK2API_BASE_URL=http://grok2api:8000 \
  -v quality_guard_state:/var/lib/grok2api-quality-guard \
  ghcr.io/<owner>/<repo>/quality-guard:latest --once
```

## Resource profile

Polling process only: no browser, no headless engine, no per-request work. One
probe per node per active interval. Steady state is a few MB of RSS and
near-zero CPU, so no special limits are needed.

Do **not** commit `quality-guard.env`, `bootstrap.json`, admin passwords, or node
proxy URLs.

See `QUALITY_GUARD.md` for detection semantics and recovery behaviour.
