# Container mode: application image built on the staging machine and
# exported as an archive (docker save). The target loads it locally with
# docker load; no registry access at any point on the target.
#
# The base is Ubuntu 24.04 pinned by digest, with the CPython 3.12 packages
# the platform baseline (scripts/prepare_baseline_image.sh) installs, so the
# image never depends on a locally built tag no registry can vouch for.
ARG BASE_IMAGE=ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3.12 python3.12-venv python3.12-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python3

# Application wheels are copied from the offline bundle wheelhouse only.
COPY wheelhouse/ /opt/udbmcp/wheelhouse/
COPY requirements/runtime.lock /opt/udbmcp/requirements/runtime.lock

RUN python3 -m venv /opt/udbmcp/venv && \
    PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 \
    /opt/udbmcp/venv/bin/python -m pip --isolated --disable-pip-version-check install \
      --no-index --no-cache-dir \
      --find-links=/opt/udbmcp/wheelhouse \
      --only-binary=:all: --require-hashes \
      -r /opt/udbmcp/requirements/runtime.lock && \
    rm -rf /opt/udbmcp/wheelhouse

# Dedicated non-root runtime identity; writable paths explicit.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin udbmcp \
    && mkdir -p /var/lib/universal-db-mcp /var/log/universal-db-mcp /etc/universal-db-mcp \
    && chown -R udbmcp:udbmcp /var/lib/universal-db-mcp /var/log/universal-db-mcp

COPY config-templates/config.yaml /etc/universal-db-mcp/config.example.yaml

USER udbmcp
ENV UDBMCP_CONFIG=/etc/universal-db-mcp/config.yaml

# stdio is the default transport (Claude Code local mode); http deployments
# use compose.offline.yaml with an authenticated, internally-restricted port.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 8765), 2).close()"]
ENTRYPOINT ["/opt/udbmcp/venv/bin/python", "-m", "universal_db_mcp"]
CMD ["serve", "--transport", "stdio"]
