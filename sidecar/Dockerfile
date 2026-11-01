# Quality Guard sidecar for grok2api -- official admin-API wiring.
#
# Deliberately standalone so a compose file only needs an image reference:
#
#   quality-guard:
#     image: ghcr.io/<owner>/<repo>/quality-guard:latest
#
# The sidecar authenticates against the official admin API
# (POST /api/admin/v1/auth/login) and drives
# /api/admin/v1/egress-quality-guard/*, so it needs NO internal bootstrap
# token and NO access to the grok2api state volume.
#
# Standard library only: no pip install, no build toolchain.

FROM python:3.12-alpine

ARG BUILD_REVISION=dev
LABEL org.opencontainers.image.title="grok2api-egress-quality-guard" \
      org.opencontainers.image.description="Standalone Quality Guard sidecar for grok2api egress nodes (admin API)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${BUILD_REVISION}"

RUN addgroup -S -g 10001 quality-guard \
 && adduser -S -D -H -u 10001 -G quality-guard quality-guard

COPY sidecar/quality_guard.py /usr/local/bin/grok2api-egress-quality-guard
RUN chmod 0755 /usr/local/bin/grok2api-egress-quality-guard

# Only used for the optional guard-owned state cache; the container can run
# with no volume at all when QUALITY_GUARD_STATE_DIR points at a tmpfs.
RUN mkdir -p /var/lib/grok2api-quality-guard \
 && chown -R quality-guard:quality-guard /var/lib/grok2api-quality-guard \
 && chmod 0700 /var/lib/grok2api-quality-guard
VOLUME ["/var/lib/grok2api-quality-guard"]

USER quality-guard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GROK2API_BASE_URL=http://grok2api:8000 \
    QUALITY_GUARD_MODE=hybrid

# Give the guard time to persist state and release guard-owned nodes.
STOPSIGNAL SIGTERM

ENTRYPOINT ["python3", "/usr/local/bin/grok2api-egress-quality-guard"]
CMD []
