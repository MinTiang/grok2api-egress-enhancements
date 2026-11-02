# Quality Guard sidecar for grok2api -- drop-in replacement for the official
# tools/egress-quality-guard Dockerfile, published so compose can pull it.
#
# Identical runtime contract to upstream:
#   * reads /var/lib/grok2api-quality-guard/bootstrap.json written by grok2api
#   * a scoped internal token from that file authorises
#     /api/internal/v1/quality-guard/*
#   * GROK2API_BASE_URL is the only environment variable needed
#
# Compose usage mirrors upstream exactly:
#
#   egress-quality-guard:
#     image: ghcr.io/<owner>/<repo>/quality-guard:latest
#     profiles: ["quality-guard"]
#     environment:
#       GROK2API_BASE_URL: ${GROK2API_BASE_URL:-http://grok2api:8000}
#     depends_on:
#       grok2api:
#         condition: service_healthy
#     volumes:
#       - quality_guard_state:/var/lib/grok2api-quality-guard
#     restart: "on-failure:5"
#     init: true
#     stop_grace_period: 30s
#     security_opt:
#       - no-new-privileges:true
#
# Standard library only: no pip install, no build toolchain.

FROM python:3.12-alpine

ARG BUILD_REVISION=dev
LABEL org.opencontainers.image.title="grok2api-egress-quality-guard" \
      org.opencontainers.image.description="Quality Guard sidecar for grok2api egress nodes" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${BUILD_REVISION}"

RUN addgroup -S -g 10001 quality-guard \
 && adduser -S -D -H -u 10001 -G quality-guard quality-guard \
 && mkdir -p /var/lib/grok2api-quality-guard \
 && chown -R quality-guard:quality-guard /var/lib/grok2api-quality-guard \
 && chmod 0700 /var/lib/grok2api-quality-guard

COPY sidecar/quality_guard.py /usr/local/bin/grok2api-egress-quality-guard
COPY sidecar/preflight.py /usr/local/bin/quality-guard-preflight
RUN chmod 0755 /usr/local/bin/grok2api-egress-quality-guard /usr/local/bin/quality-guard-preflight

VOLUME ["/var/lib/grok2api-quality-guard"]

USER quality-guard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GROK2API_BASE_URL=http://grok2api:8000

# The guard traps SIGTERM to persist state and release guard-owned nodes.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/grok2api-egress-quality-guard"]
CMD []
