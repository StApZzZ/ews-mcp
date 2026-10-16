# syntax=docker/dockerfile:1
# ews-mcp 4.5 — multi-stage, non-root from the start, import-gated build.
#
# REGISTRY: optional pull-through mirror prefix WITH a trailing slash
# (e.g. "mirror.example.com/"). Empty → Docker Hub ("library/python" resolves
# to docker.io/library/python). CI passes it from $MIRROR_DOCKERHUB.
ARG REGISTRY=""
# Exact interpreter + Debian release: no floating tags anywhere.
ARG PYTHON_IMAGE_TAG=3.15.0-slim-trixie

FROM ${REGISTRY}library/python:${PYTHON_IMAGE_TAG} AS builder
# Optional private PyPI mirror for closed networks: --build-arg PIP_INDEX_URL=...
# Declared without a default so pip's own default applies when it is not
# passed. Lives in the builder stage only — never reaches the runtime image.
ARG PIP_INDEX_URL
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY pyproject.toml requirements.lock ./
COPY ewsmcp ./ewsmcp
# Every transitive dependency comes from requirements.lock (constraints).
# pip itself is removed from the venv once the app is installed: nothing
# installs packages at runtime, and pip's vendored libraries
# (pip/_vendor/vendor.txt: urllib3, msgpack, setuptools…) lag behind upstream
# fixes and would trip the Trivy HIGH/CRITICAL gate on their own.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install pip==26.2.1 \
    && /opt/venv/bin/pip install -c requirements.lock . \
    && /opt/venv/bin/python -m pip uninstall -y pip

FROM ${REGISTRY}library/python:${PYTHON_IMAGE_TAG}
# OS security fixes released after the base image was cut: the Trivy gate runs
# on HIGH/CRITICAL with --ignore-unfixed, so "fix available" must mean "applied".
# The base image's system pip is unused at runtime (the app lives in /opt/venv,
# which ships without pip too) — drop it to shrink the CVE surface.
# Non-root from the first layer — no root+gosu dance. DATA_DIR points at a
# volume pre-chowned here so the unprivileged user can write it.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip \
    && groupadd -r mcp && useradd -r -g mcp -d /home/mcp -m mcp \
    && mkdir -p /data && chown mcp:mcp /data
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000
# Build gate: the application must IMPORT — never grep for version strings
# (the v3 Dockerfile's stale version-grep was a build landmine).
RUN python -c "import ewsmcp.main"
USER mcp
VOLUME /data
EXPOSE 8000
# /livez answers the moment the process is up (never-exit boot): a cold
# Exchange must NOT make the container unhealthy — that is /readyz's job.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/livez', timeout=3).status==200 else 1)"
CMD ["ewsmcp"]
