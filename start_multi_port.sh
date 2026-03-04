#!/bin/bash
# start_multi_port.sh — Launch 3 FastAPI instances on separate ports

set -e

# Load environment variables from .env (if present)
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check required env vars
if [ -z "$JWT_SECRET_KEY" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "ERROR: Missing required env vars: JWT_SECRET_KEY, ADMIN_TOKEN" >&2
    exit 1
fi

echo "Starting AnsibleRelay multi-port server..."
echo "Port 7770 : Client (enrollment + WSS)"
echo "Port 7771 : Plugin connection (exec/upload/fetch)"
echo "Port 7772 : Inventory plugin"
echo ""

# Start 3 hypercorn workers (one per port)
hypercorn server.api.main_multi_port:app_client --bind 0.0.0.0:7770 &
PID_7770=$!
echo "✓ Started app_client on port 7770 (PID: $PID_7770)"

hypercorn server.api.main_multi_port:app_plugin --bind 0.0.0.0:7771 &
PID_7771=$!
echo "✓ Started app_plugin on port 7771 (PID: $PID_7771)"

hypercorn server.api.main_multi_port:app_inventory --bind 0.0.0.0:7772 &
PID_7772=$!
echo "✓ Started app_inventory on port 7772 (PID: $PID_7772)"

# Wait for all PIDs
wait $PID_7770 $PID_7771 $PID_7772

echo "All servers stopped"
