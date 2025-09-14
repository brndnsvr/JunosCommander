#!/bin/bash
#
# PostgreSQL Backup Script for JunosCommander
# Supports full dumps, schema-only, and point-in-time recovery backups
#
# Usage: ./postgres_backup.sh [--type full|schema|incremental] [--retention-days N]
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BACKUP_DIR="$PROJECT_ROOT/backups"
LOG_FILE="$BACKUP_DIR/backup.log"

# Default values
BACKUP_TYPE="full"
RETENTION_DAYS=30
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Database configuration (from environment or defaults)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-junoscommander}"
DB_USER="${DB_USER:-junoscommander_backup}"
PGPASSWORD="${DB_PASSWORD:-}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            BACKUP_TYPE="$2"
            shift 2
            ;;
        --retention-days)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--type full|schema|incremental] [--retention-days N]"
            echo ""
            echo "Options:"
            echo "  --type TYPE             Backup type: full, schema, or incremental (default: full)"
            echo "  --retention-days N      Keep backups for N days (default: 30)"
            echo "  -h, --help             Show this help message"
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
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Setup backup directories
setup_directories() {
    log_info "Setting up backup directories..."

    mkdir -p "$BACKUP_DIR"/{full,schema,incremental,wal,logs}
    mkdir -p "$BACKUP_DIR/archive"

    # Ensure log file exists
    touch "$LOG_FILE"

    log_success "Backup directories ready"
}

# Check PostgreSQL connection
check_connection() {
    log_info "Testing PostgreSQL connection..."

    if ! PGPASSWORD="$PGPASSWORD" pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"; then
        log_error "Cannot connect to PostgreSQL database"
        exit 1
    fi

    log_success "PostgreSQL connection successful"
}

# Full database backup
backup_full() {
    log_info "Creating full database backup..."

    local backup_file="$BACKUP_DIR/full/junoscommander_full_$TIMESTAMP.sql"
    local compressed_file="$backup_file.gz"

    # Create full backup with custom format for faster restore
    if PGPASSWORD="$PGPASSWORD" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --format=custom \
        --compress=6 \
        --file="$backup_file.custom"; then

        # Also create SQL dump for readability
        PGPASSWORD="$PGPASSWORD" pg_dump \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            -d "$DB_NAME" \
            --verbose \
            --no-owner \
            --no-privileges > "$backup_file"

        # Compress SQL dump
        gzip "$backup_file"

        local backup_size=$(du -h "$backup_file.custom" | cut -f1)
        local sql_size=$(du -h "$compressed_file" | cut -f1)

        log_success "Full backup completed successfully"
        log_info "Custom format backup: $backup_file.custom ($backup_size)"
        log_info "SQL dump backup: $compressed_file ($sql_size)"

        # Create backup metadata
        cat > "$backup_file.meta" <<EOF
{
    "backup_type": "full",
    "timestamp": "$TIMESTAMP",
    "database": "$DB_NAME",
    "host": "$DB_HOST",
    "format": "custom",
    "size": "$backup_size",
    "compression": "6"
}
EOF

        return 0
    else
        log_error "Full backup failed"
        return 1
    fi
}

# Schema-only backup
backup_schema() {
    log_info "Creating schema-only backup..."

    local backup_file="$BACKUP_DIR/schema/junoscommander_schema_$TIMESTAMP.sql"

    if PGPASSWORD="$PGPASSWORD" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --schema-only \
        --no-owner \
        --no-privileges > "$backup_file"; then

        gzip "$backup_file"
        local backup_size=$(du -h "$backup_file.gz" | cut -f1)

        log_success "Schema backup completed successfully"
        log_info "Schema backup: $backup_file.gz ($backup_size)"

        return 0
    else
        log_error "Schema backup failed"
        return 1
    fi
}

# WAL archive backup (for point-in-time recovery)
backup_wal() {
    log_info "Archiving WAL files..."

    local wal_source="/var/lib/postgresql/wal_archive"
    local wal_backup="$BACKUP_DIR/wal/wal_archive_$TIMESTAMP"

    if [[ -d "$wal_source" ]]; then
        mkdir -p "$wal_backup"

        # Copy WAL files that are older than 1 hour
        find "$wal_source" -name "*.backup" -o -name "*[0-9A-F]" -type f -mmin +60 \
            -exec cp {} "$wal_backup/" \;

        # Create archive
        tar -czf "$wal_backup.tar.gz" -C "$BACKUP_DIR/wal" "$(basename "$wal_backup")"
        rm -rf "$wal_backup"

        local archive_size=$(du -h "$wal_backup.tar.gz" | cut -f1)
        log_success "WAL archive completed: $wal_backup.tar.gz ($archive_size)"
    else
        log_warn "WAL archive directory not found: $wal_source"
    fi
}

# Incremental backup using pg_basebackup
backup_incremental() {
    log_info "Creating incremental backup..."

    local backup_dir="$BACKUP_DIR/incremental/basebackup_$TIMESTAMP"

    if PGPASSWORD="$PGPASSWORD" pg_basebackup \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -D "$backup_dir" \
        --format=tar \
        --gzip \
        --progress \
        --verbose \
        --wal-method=stream; then

        local backup_size=$(du -sh "$backup_dir" | cut -f1)

        log_success "Incremental backup completed successfully"
        log_info "Incremental backup: $backup_dir ($backup_size)"

        return 0
    else
        log_error "Incremental backup failed"
        return 1
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."

    local cleanup_count=0

    # Cleanup full backups
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((cleanup_count++))
    done < <(find "$BACKUP_DIR/full" -name "*.sql.gz" -o -name "*.custom" -o -name "*.meta" -mtime +$RETENTION_DAYS -print0)

    # Cleanup schema backups
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((cleanup_count++))
    done < <(find "$BACKUP_DIR/schema" -name "*.sql.gz" -mtime +$RETENTION_DAYS -print0)

    # Cleanup incremental backups
    while IFS= read -r -d '' dir; do
        rm -rf "$dir"
        ((cleanup_count++))
    done < <(find "$BACKUP_DIR/incremental" -maxdepth 1 -type d -name "basebackup_*" -mtime +$RETENTION_DAYS -print0)

    # Cleanup WAL archives (keep longer for PITR)
    local wal_retention=$((RETENTION_DAYS * 2))
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((cleanup_count++))
    done < <(find "$BACKUP_DIR/wal" -name "*.tar.gz" -mtime +$wal_retention -print0)

    if [[ $cleanup_count -gt 0 ]]; then
        log_info "Cleaned up $cleanup_count old backup files"
    else
        log_info "No old backup files to clean up"
    fi
}

# Generate backup report
generate_report() {
    log_info "Generating backup report..."

    local report_file="$BACKUP_DIR/backup_report_$TIMESTAMP.txt"

    cat > "$report_file" <<EOF
JunosCommander Database Backup Report

Backup Date: $(date)
Backup Type: $BACKUP_TYPE
Database: $DB_NAME
Host: $DB_HOST

Backup Statistics:
------------------
$(find "$BACKUP_DIR" -name "*_$TIMESTAMP*" -type f -exec ls -lh {} \;)

Disk Usage:
-----------
$(du -sh "$BACKUP_DIR"/* 2>/dev/null || echo "No backup directories found")

Recent Backups (last 7 days):
-----------------------------
Full Backups:
$(find "$BACKUP_DIR/full" -name "*.custom" -mtime -7 -exec ls -lh {} \; | head -5)

Schema Backups:
$(find "$BACKUP_DIR/schema" -name "*.sql.gz" -mtime -7 -exec ls -lh {} \; | head -5)

Incremental Backups:
$(find "$BACKUP_DIR/incremental" -maxdepth 1 -type d -name "basebackup_*" -mtime -7 | head -5)

WAL Archives:
$(find "$BACKUP_DIR/wal" -name "*.tar.gz" -mtime -7 -exec ls -lh {} \; | head -5)

Database Status:
----------------
$(PGPASSWORD="$PGPASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT
    pg_size_pretty(pg_database_size('$DB_NAME')) as database_size,
    (SELECT count(*) FROM devices) as device_count,
    (SELECT count(*) FROM users) as user_count,
    (SELECT count(*) FROM tasks) as task_count;
" 2>/dev/null || echo "Could not retrieve database statistics")

EOF

    log_success "Backup report generated: $report_file"
}

# Send notification (optional)
send_notification() {
    local status="$1"
    local message="$2"

    # Example: Send to Slack webhook (configure SLACK_WEBHOOK_URL)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        local color="good"
        if [[ "$status" == "error" ]]; then
            color="danger"
        fi

        curl -X POST -H 'Content-type: application/json' \
            --data "{\"attachments\":[{\"color\":\"$color\",\"text\":\"$message\"}]}" \
            "$SLACK_WEBHOOK_URL" 2>/dev/null || true
    fi

    # Example: Send email (requires mailutils)
    if [[ -n "${NOTIFICATION_EMAIL:-}" ]] && command -v mail &> /dev/null; then
        echo "$message" | mail -s "JunosCommander Backup $status" "$NOTIFICATION_EMAIL" || true
    fi
}

# Main execution
main() {
    log_info "Starting JunosCommander database backup"
    log_info "Backup type: $BACKUP_TYPE"
    log_info "Retention: $RETENTION_DAYS days"

    setup_directories
    check_connection

    local success=true
    local message="JunosCommander backup completed successfully"

    case "$BACKUP_TYPE" in
        "full")
            if ! backup_full; then
                success=false
                message="JunosCommander full backup failed"
            else
                backup_wal  # Also archive WAL files with full backup
            fi
            ;;
        "schema")
            if ! backup_schema; then
                success=false
                message="JunosCommander schema backup failed"
            fi
            ;;
        "incremental")
            if ! backup_incremental; then
                success=false
                message="JunosCommander incremental backup failed"
            fi
            ;;
        *)
            log_error "Invalid backup type: $BACKUP_TYPE"
            exit 1
            ;;
    esac

    if [[ "$success" == "true" ]]; then
        cleanup_old_backups
        generate_report
        log_success "Backup process completed successfully"
        send_notification "success" "$message"
    else
        log_error "Backup process failed"
        send_notification "error" "$message"
        exit 1
    fi
}

# Load environment variables if .env file exists
if [[ -f "$PROJECT_ROOT/.env.production" ]]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env.production" | xargs)
fi

# Run main function
main "$@"