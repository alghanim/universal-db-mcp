# Container mode: application image built on the staging machine and
# exported as an archive (docker save). The target loads it locally with
# docker load; no registry access at any point on the target.
FROM udbmcp-baseline:ubuntu24.04-cp312

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
