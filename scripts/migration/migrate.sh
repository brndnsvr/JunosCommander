#!/bin/bash
#
# JunosCommander Database Migration Script
# Migrates from SQLite development database to PostgreSQL production
#
# Usage: ./migrate.sh [--dry-run] [--sqlite-path path] [--env-file path]
#

set -euo pipefail

# Default paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEFAULT_SQLITE_PATH="$PROJECT_ROOT/data/junoscommander.db"
DEFAULT_ENV_FILE="$PROJECT_ROOT/.env.production"

# Parse command line arguments
DRY_RUN=false
SQLITE_PATH="$DEFAULT_SQLITE_PATH"
ENV_FILE="$DEFAULT_ENV_FILE"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --sqlite-path)
            SQLITE_PATH="$2"
            shift 2
            ;;
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--sqlite-path path] [--env-file path]"
            echo ""
            echo "Options:"
            echo "  --dry-run           Validate connections without migrating data"
            echo "  --sqlite-path PATH  Path to SQLite database (default: $DEFAULT_SQLITE_PATH)"
            echo "  --env-file PATH     Environment file with PostgreSQL config (default: $DEFAULT_ENV_FILE)"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not found"
        exit 1
    fi

    # Check if pip is available
    if ! python3 -m pip --version &> /dev/null; then
        log_error "pip is required but not found"
        exit 1
    fi

    # Check if SQLite database exists
    if [[ ! -f "$SQLITE_PATH" ]]; then
        log_error "SQLite database not found at: $SQLITE_PATH"
        exit 1
    fi

    # Check if environment file exists
    if [[ ! -f "$ENV_FILE" ]]; then
        log_warn "Environment file not found at: $ENV_FILE"
        log_info "Please ensure PostgreSQL connection details are available via environment variables"
    fi

    log_success "Prerequisites check passed"
}

# Setup Python virtual environment and install dependencies
setup_python_env() {
    log_info "Setting up Python environment..."

    cd "$SCRIPT_DIR"

    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        log_info "Installing Python dependencies..."
        pip install -r requirements.txt
    else
        log_info "Installing migration dependencies directly..."
        pip install psycopg2-binary python-dotenv
    fi

    log_success "Python environment ready"
}

# Backup SQLite database
backup_sqlite() {
    log_info "Creating SQLite database backup..."

    local backup_dir="$PROJECT_ROOT/backups/migration"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="$backup_dir/junoscommander_sqlite_backup_$timestamp.db"

    mkdir -p "$backup_dir"
    cp "$SQLITE_PATH" "$backup_file"

    log_success "SQLite backup created: $backup_file"
}

# Check PostgreSQL connectivity
check_postgres_connection() {
    log_info "Testing PostgreSQL connection..."

    cd "$SCRIPT_DIR"
    source venv/bin/activate

    # Load environment file if it exists
    if [[ -f "$ENV_FILE" ]]; then
        log_info "Loading environment from: $ENV_FILE"
        export $(grep -v '^#' "$ENV_FILE" | xargs)
    fi

    # Test connection with dry-run
    if python3 sqlite_to_postgres.py --sqlite-db "$SQLITE_PATH" --dry-run; then
        log_success "PostgreSQL connection test passed"
        return 0
    else
        log_error "PostgreSQL connection test failed"
        return 1
    fi
}

# Run the migration
run_migration() {
    log_info "Starting database migration..."

    cd "$SCRIPT_DIR"
    source venv/bin/activate

    # Load environment file if it exists
    if [[ -f "$ENV_FILE" ]]; then
        export $(grep -v '^#' "$ENV_FILE" | xargs)
    fi

    local migration_args="--sqlite-db $SQLITE_PATH"

    if [[ "$DRY_RUN" == "true" ]]; then
        migration_args="$migration_args --dry-run"
        log_info "Running migration in dry-run mode..."
    else
        log_info "Running actual migration..."
        log_warn "This will modify the PostgreSQL database!"
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Migration cancelled"
            exit 0
        fi
    fi

    if python3 sqlite_to_postgres.py $migration_args; then
        log_success "Migration completed successfully!"
        return 0
    else
        log_error "Migration failed!"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Deactivate virtual environment if active
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        deactivate || true
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    log_info "JunosCommander Database Migration"
    log_info "=================================="
    log_info "SQLite path: $SQLITE_PATH"
    log_info "Environment file: $ENV_FILE"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Mode: Dry run (validation only)"
    else
        log_info "Mode: Full migration"
    fi
    echo

    # Run migration steps
    check_prerequisites
    setup_python_env

    if [[ "$DRY_RUN" == "false" ]]; then
        backup_sqlite
    fi

    check_postgres_connection
    run_migration

    echo
    log_success "Migration process completed!"

    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Next steps:"
        log_info "1. Update your application configuration to use PostgreSQL"
        log_info "2. Test the application with the new database"
        log_info "3. Monitor the application logs for any issues"
        log_info "4. Consider setting up database monitoring and backups"
    fi
}

# Run main function
main "$@"