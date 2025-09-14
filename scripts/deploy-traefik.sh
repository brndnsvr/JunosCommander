#!/bin/bash

# JunosCommander Traefik Deployment Script
# This script sets up and deploys JunosCommander with Traefik reverse proxy

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env.traefik"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.traefik.yml"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi

    # Check if Docker Compose is available
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not available. Please install Docker Compose."
        exit 1
    fi

    # Check if required files exist
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        print_error "Docker Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    print_success "Prerequisites check completed"
}

# Function to setup environment
setup_environment() {
    print_status "Setting up environment..."

    # Copy environment template if .env doesn't exist
    if [[ ! -f "$PROJECT_DIR/.env" ]]; then
        if [[ -f "$ENV_FILE" ]]; then
            cp "$ENV_FILE" "$PROJECT_DIR/.env"
            print_warning "Environment file created from template. Please review and customize $PROJECT_DIR/.env"
        else
            print_error "Environment template not found: $ENV_FILE"
            exit 1
        fi
    fi

    # Create necessary directories
    mkdir -p "$PROJECT_DIR/data"
    mkdir -p "$PROJECT_DIR/logs/traefik"
    mkdir -p "$PROJECT_DIR/logs/app"
    mkdir -p "$PROJECT_DIR/traefik/certificates"

    # Set proper permissions
    chmod 600 "$PROJECT_DIR/.env" 2>/dev/null || true
    chmod 700 "$PROJECT_DIR/traefik/certificates" 2>/dev/null || true

    print_success "Environment setup completed"
}

# Function to validate configuration
validate_configuration() {
    print_status "Validating configuration..."

    # Source environment variables
    if [[ -f "$PROJECT_DIR/.env" ]]; then
        source "$PROJECT_DIR/.env"
    fi

    # Check critical environment variables
    local missing_vars=()

    # Check domain configuration
    if [[ -z "${JUNOSCOMMANDER_DOMAIN:-}" ]]; then
        missing_vars+=("JUNOSCOMMANDER_DOMAIN")
    fi

    if [[ -z "${LETSENCRYPT_EMAIL:-}" ]]; then
        missing_vars+=("LETSENCRYPT_EMAIL")
    fi

    # Check if domains are still using example.com
    if [[ "${JUNOSCOMMANDER_DOMAIN:-}" == *"example.com" ]]; then
        print_warning "Domain configuration still uses example.com. Please update your domains in .env"
    fi

    if [[ "${LETSENCRYPT_EMAIL:-}" == *"example.com" ]]; then
        print_warning "Let's Encrypt email still uses example.com. Please update in .env"
    fi

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "Missing required environment variables: ${missing_vars[*]}"
        print_error "Please configure these variables in $PROJECT_DIR/.env"
        exit 1
    fi

    print_success "Configuration validation completed"
}

# Function to generate dashboard password
generate_dashboard_password() {
    local username="${1:-admin}"
    local password="$2"

    if command -v htpasswd &> /dev/null; then
        htpasswd -nb "$username" "$password"
    else
        # Fallback using openssl if htpasswd is not available
        if command -v openssl &> /dev/null; then
            echo -n "$username:$(openssl passwd -apr1 "$password")"
        else
            print_error "Neither htpasswd nor openssl is available. Cannot generate dashboard password."
            exit 1
        fi
    fi
}

# Function to initialize certificates directory
init_certificates() {
    print_status "Initializing certificates..."

    local cert_dir="$PROJECT_DIR/traefik/certificates"

    # Create acme.json with proper permissions
    touch "$cert_dir/acme.json"
    chmod 600 "$cert_dir/acme.json"

    print_success "Certificates initialized"
}

# Function to start services
start_services() {
    print_status "Starting services..."

    cd "$PROJECT_DIR"

    # Pull latest images
    docker compose -f "$COMPOSE_FILE" pull

    # Start services
    docker compose -f "$COMPOSE_FILE" up -d

    print_success "Services started successfully"
}

# Function to check service health
check_health() {
    print_status "Checking service health..."

    local services=("traefik" "junoscommander" "openldap")
    local max_retries=30
    local retry_interval=5

    for service in "${services[@]}"; do
        print_status "Checking health of $service..."

        local retries=0
        while [[ $retries -lt $max_retries ]]; do
            if docker compose -f "$COMPOSE_FILE" ps "$service" | grep -q "healthy\|Up"; then
                print_success "$service is healthy"
                break
            fi

            retries=$((retries + 1))
            if [[ $retries -eq $max_retries ]]; then
                print_warning "$service health check timed out"
                break
            fi

            sleep $retry_interval
        done
    done

    # Check Traefik API
    local traefik_url="http://localhost:8080/api/overview"
    if curl -sf "$traefik_url" > /dev/null 2>&1; then
        print_success "Traefik API is accessible"
    else
        print_warning "Traefik API is not accessible"
    fi
}

# Function to display status
show_status() {
    print_status "Deployment Status:"
    echo

    # Show running containers
    docker compose -f "$COMPOSE_FILE" ps
    echo

    # Show service URLs (if domains are configured)
    if [[ -f "$PROJECT_DIR/.env" ]]; then
        source "$PROJECT_DIR/.env"

        echo "Service URLs:"
        echo "  Traefik Dashboard: https://${TRAEFIK_DOMAIN:-traefik.example.com}/dashboard/"
        echo "  JunosCommander:    https://${JUNOSCOMMANDER_DOMAIN:-junoscommander.example.com}/"
        echo "  LDAP Admin:        https://${LDAP_ADMIN_DOMAIN:-ldap-admin.example.com}/"

        if [[ -v PROMETHEUS_DOMAIN ]]; then
            echo "  Prometheus:        https://${PROMETHEUS_DOMAIN}/"
        fi

        if [[ -v GRAFANA_DOMAIN ]]; then
            echo "  Grafana:           https://${GRAFANA_DOMAIN}/"
        fi
        echo
    fi

    echo "Logs:"
    echo "  Traefik logs: docker compose -f $COMPOSE_FILE logs -f traefik"
    echo "  App logs:     docker compose -f $COMPOSE_FILE logs -f junoscommander"
    echo "  All logs:     docker compose -f $COMPOSE_FILE logs -f"
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."
    cd "$PROJECT_DIR"
    docker compose -f "$COMPOSE_FILE" down
    print_success "Services stopped"
}

# Function to cleanup
cleanup() {
    print_status "Cleaning up..."
    cd "$PROJECT_DIR"
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
    docker system prune -f
    print_success "Cleanup completed"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  deploy      Deploy JunosCommander with Traefik (default)"
    echo "  start       Start services"
    echo "  stop        Stop services"
    echo "  restart     Restart services"
    echo "  status      Show deployment status"
    echo "  logs        Show service logs"
    echo "  cleanup     Stop services and clean up volumes"
    echo "  genpass     Generate password hash for dashboard auth"
    echo "  help        Show this help message"
    echo
    echo "Examples:"
    echo "  $0 deploy           # Full deployment"
    echo "  $0 start            # Start existing deployment"
    echo "  $0 status           # Check status"
    echo "  $0 genpass mypass   # Generate password hash"
}

# Main deployment function
deploy() {
    print_status "Starting JunosCommander deployment with Traefik..."

    check_prerequisites
    setup_environment
    validate_configuration
    init_certificates
    start_services

    # Wait a bit for services to initialize
    sleep 10

    check_health
    show_status

    print_success "Deployment completed!"
    print_status "Please review the service URLs above and ensure DNS records are configured correctly."
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    start)
        check_prerequisites
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        sleep 5
        start_services
        ;;
    status)
        show_status
        ;;
    logs)
        cd "$PROJECT_DIR"
        docker compose -f "$COMPOSE_FILE" logs -f "${2:-}"
        ;;
    cleanup)
        cleanup
        ;;
    genpass)
        if [[ -z "${2:-}" ]]; then
            print_error "Usage: $0 genpass <password>"
            exit 1
        fi
        generate_dashboard_password "admin" "$2"
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac