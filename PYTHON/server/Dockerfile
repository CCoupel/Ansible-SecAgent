# Dockerfile — AnsibleRelay relay-server (multi-port)
#
# Build context: repo root (docker-compose.yml uses context: .)
# Supports 3 independent ports:
#   - Port 7770 : Client (enrollment + WSS)
#   - Port 7771 : Plugin connection (exec/upload/fetch)
#   - Port 7772 : Inventory plugin
#
# Launch via docker-compose or:
#   hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 &
#   hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 &
#   hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772

FROM python:3.11-slim

# Non-root user for security (NoNewPrivileges equivalent)
RUN groupadd --system relay && useradd --system --gid relay --no-create-home relay

WORKDIR /app

# Install dependencies first (layer caching)
COPY server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir hypercorn

# Copy server package
COPY server/ /app/server/

# Data directory for SQLite (volume mount point)
RUN mkdir -p /data && chown relay:relay /data

USER relay

EXPOSE 7770 7771 7772

# Healthcheck via port 7770 (client)
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:7770/health')"

# Launch all 3 apps via a shell script or directly
CMD ["/bin/bash", "-c", \
     "hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 & \
      hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 & \
      hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772 && \
      wait"]
