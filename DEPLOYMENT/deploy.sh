#!/bin/bash
# Ansible-SecAgent Deployment Script
# Usage:
#   ./deploy.sh server       — Deploy relay server only
#   ./deploy.sh minion       — Deploy relay minions only
#   ./deploy.sh ansible      — Deploy Ansible container with relay plugins
#   ./deploy.sh all          — Deploy server, minions, and Ansible container
#   ./deploy.sh stop         — Stop all containers
#   ./deploy.sh status       — Show status of containers

set -e

DOCKER_HOST="${DOCKER_HOST:-tcp://192.168.1.218:2375}"
export DOCKER_HOST

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/ansible_server"
MINION_DIR="$SCRIPT_DIR/ansible_minion"
QUALIF_DIR="$SCRIPT_DIR/qualif"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[*]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[x]${NC} $1"
}

deploy_server() {
    log_info "Deploying RELAY SERVER (nats + relay-api + caddy)..."
    cd "$SERVER_DIR"
    docker compose up --build -d

    log_info "Waiting for server to be healthy..."
    sleep 15

    if curl -s http://192.168.1.218:7770/health | grep -q "ok"; then
        log_info "✅ Server is healthy"
    else
        log_warn "Server health check may not be ready yet"
    fi
}

deploy_minions() {
    log_info "Deploying RELAY MINIONS (secagent-minion-01/02/03)..."
    cd "$MINION_DIR"
    docker compose up --build -d

    log_info "Waiting for minions to start..."
    sleep 10

    log_info "Checking agent status..."
    for i in 01 02 03; do
        status=$(docker logs secagent-minion-$i 2>&1 | grep -o "WebSocket connecté" | tail -1)
        if [ -n "$status" ]; then
            log_info "✅ Agent $i connected"
        else
            log_warn "⚠️  Agent $i status unknown - check logs with: docker logs secagent-minion-$i"
        fi
    done
}

deploy_ansible() {
    log_info "Deploying ANSIBLE CONTAINER (with relay plugins)..."

    # Check if docker-compose.ansible.yml exists
    if [ ! -f "$QUALIF_DIR/docker-compose.ansible.yml" ]; then
        log_error "docker-compose.ansible.yml not found in $QUALIF_DIR"
        exit 1
    fi

    cd "$QUALIF_DIR"

    # Set environment variables if not already set
    if [ -z "$RELAY_SERVER_URL" ]; then
        export RELAY_SERVER_URL="http://relay-api:7770"
        log_info "Using default RELAY_SERVER_URL: $RELAY_SERVER_URL"
    fi

    if [ -z "$RELAY_ADMIN_TOKEN" ]; then
        log_warn "RELAY_ADMIN_TOKEN not set - container may not work correctly"
        log_info "Set it with: export RELAY_ADMIN_TOKEN='your-token-here'"
    fi

    # Create playbooks and inventory directories if they don't exist
    mkdir -p playbooks inventory roles

    # Deploy ansible container
    docker compose -f docker-compose.ansible.yml up --build -d

    log_info "Waiting for Ansible container to start..."
    sleep 5

    if docker ps | grep -q relay-ansible; then
        log_info "✅ Ansible container is running"
        log_info "Usage: docker exec -it relay-ansible bash"
        log_info "Example: docker exec -it relay-ansible ansible-inventory -i secagent_inventory -y"
    else
        log_warn "⚠️  Ansible container status unknown - check logs with: docker logs relay-ansible"
    fi
}

stop_all() {
    log_info "Stopping all containers..."

    log_info "Stopping Ansible container..."
    cd "$QUALIF_DIR"
    docker compose -f docker-compose.ansible.yml down 2>/dev/null || true

    log_info "Stopping minions..."
    cd "$MINION_DIR"
    docker compose down 2>/dev/null || true

    log_info "Stopping server..."
    cd "$SERVER_DIR"
    docker compose down 2>/dev/null || true

    log_info "✅ All containers stopped"
}

show_status() {
    log_info "RELAY SERVER status:"
    cd "$SERVER_DIR"
    docker compose ps

    echo ""
    log_info "RELAY MINIONS status:"
    cd "$MINION_DIR"
    docker compose ps

    echo ""
    log_info "ANSIBLE CONTAINER status:"
    cd "$QUALIF_DIR"
    docker compose -f docker-compose.ansible.yml ps
}

show_help() {
    cat << EOF
Ansible-SecAgent Deployment Script

Usage:
    ./deploy.sh [COMMAND] [OPTIONS]

Commands:
    server           Deploy relay server only (nats + relay-api + caddy)
    minion           Deploy relay minions only (secagent-minion-01/02/03)
    ansible          Deploy Ansible container with relay plugins
    all              Deploy server, minions, and Ansible container (default)
    stop             Stop all containers
    status           Show status of all containers
    logs-server      Show server logs
    logs-agent       Show agent logs (arg: 01|02|03)
    logs-ansible     Show Ansible container logs
    help             Show this help message

Options:
    DOCKER_HOST          Override Docker host (default: tcp://192.168.1.218:2375)
    RELAY_SERVER_URL     Relay server URL (default: http://relay-api:7770)
    RELAY_ADMIN_TOKEN    Admin token for Ansible container

Examples:
    ./deploy.sh all
    DOCKER_HOST=unix:///var/run/docker.sock ./deploy.sh status
    ./deploy.sh logs-agent 01
    ./deploy.sh ansible
    RELAY_ADMIN_TOKEN=my-token ./deploy.sh ansible

For more information, see DEPLOYMENT/ANSIBLE_DEPLOYMENT.md

EOF
}

# Main
case "${1:-all}" in
    server)
        deploy_server
        ;;
    minion)
        deploy_minions
        ;;
    ansible)
        deploy_ansible
        ;;
    all)
        deploy_server
        log_info ""
        deploy_minions
        log_info ""
        deploy_ansible
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    logs-server)
        docker logs relay-api --tail 50 -f
        ;;
    logs-agent)
        agent_id="${2:-01}"
        docker logs secagent-minion-$agent_id --tail 50 -f
        ;;
    logs-ansible)
        docker logs relay-ansible --tail 50 -f
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
