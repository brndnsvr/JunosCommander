# JunosCommander Production Deployment Guide

## Overview

This guide covers the complete deployment of JunosCommander in a production environment with:
- **Traefik** reverse proxy with automatic HTTPS via Let's Encrypt
- **PostgreSQL** database for scalable data storage
- **Redis** for session management and caching
- **Prometheus + Grafana** for monitoring
- **Loki** for centralized logging
- **High availability** with multiple application instances

## Architecture

```
Internet
    ↓
[Traefik] → HTTPS/TLS termination, load balancing
    ↓
[App Instances] → JunosCommander (2+ instances)
    ↓
[PostgreSQL] + [Redis] → Data persistence & caching
    ↓
[Monitoring Stack] → Prometheus, Grafana, Loki
```

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Domain name with DNS control
- 4GB+ RAM, 20GB+ disk space
- Cloudflare account (for DNS challenge) or open port 80 (for HTTP challenge)

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/yourusername/JunosCommander.git
cd JunosCommander
make -f Makefile.production setup

# 2. Configure environment
cp .env.production .env
# Edit .env with your values

# 3. Generate secure passwords
make -f Makefile.production generate-passwords

# 4. Deploy
make -f Makefile.production deploy
```

## Detailed Setup

### 1. Environment Configuration

Edit `.env` with your production values:

```bash
# Required configurations
DOMAIN=junoscommander.example.com
ACME_EMAIL=admin@example.com
CF_API_EMAIL=your-cloudflare-email
CF_DNS_API_TOKEN=your-cloudflare-api-token

# Generate secure passwords
SESSION_SECRET=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 64)
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)

# Active Directory
AD_SERVER=ldaps://ad.example.com:636
AD_BASE_DN=DC=example,DC=com
AD_SERVICE_USER=svc_junoscommander@example.com
AD_SERVICE_PASSWORD=secure-password
```

### 2. SSL Certificate Setup

#### Option A: Cloudflare DNS Challenge (Recommended)
```bash
# Set Cloudflare credentials in .env
CF_API_EMAIL=your-email@example.com
CF_DNS_API_TOKEN=your-api-token
```

#### Option B: HTTP Challenge
```bash
# Ensure port 80 is open and accessible
# Update traefik.yml to use HTTP challenge
```

### 3. Database Migration

If migrating from SQLite:
```bash
# Export from SQLite
python3 scripts/migration/sqlite_to_postgres.py

# Import to PostgreSQL
make -f Makefile.production db-migrate
```

### 4. Deploy Services

```bash
# Build and start all services
make -f Makefile.production build
make -f Makefile.production up

# Verify health
make -f Makefile.production health-check
```

## Service URLs

After deployment, services are available at:

- **Application**: https://junoscommander.example.com
- **Traefik Dashboard**: https://traefik.junoscommander.example.com
- **Grafana**: https://grafana.junoscommander.example.com
- **Prometheus**: http://localhost:9091 (internal only)

## Operations

### Monitoring

```bash
# View real-time logs
make -f Makefile.production logs

# Check metrics
make -f Makefile.production metrics

# Open Grafana dashboard
make -f Makefile.production grafana-open
```

### Backup & Restore

```bash
# Backup database
make -f Makefile.production db-backup

# Restore from backup
make -f Makefile.production db-restore BACKUP=backups/junoscommander_20240101_120000.sql.gz

# Automated daily backups (add to crontab)
0 2 * * * cd /path/to/junoscommander && make -f Makefile.production db-backup
```

### Scaling

```bash
# Scale to 3 instances
make -f Makefile.production scale-up COUNT=3

# Scale down to 1 instance
make -f Makefile.production scale-down
```

### Zero-Downtime Updates

```bash
# Pull latest code
git pull origin main

# Perform rolling update
make -f Makefile.production upgrade
```

### Maintenance Mode

```bash
# Enable maintenance mode
make -f Makefile.production maintenance-on

# Disable maintenance mode
make -f Makefile.production maintenance-off
```

## Security

### SSL/TLS Configuration

- TLS 1.2+ enforced
- Strong cipher suites only
- HSTS enabled with preload
- Automatic certificate renewal via Let's Encrypt

### Network Security

- Isolated Docker networks
- Internal services not exposed
- Rate limiting on all endpoints
- DDoS protection via Traefik

### Application Security

- Non-root containers
- Read-only root filesystems where possible
- Secrets managed via environment variables
- Regular security scanning with Trivy

### Run Security Scan

```bash
make -f Makefile.production security-scan
```

## Troubleshooting

### Common Issues

#### 1. Services Not Starting
```bash
# Check logs
docker-compose -f docker-compose.production.yml logs

# Verify environment variables
docker-compose -f docker-compose.production.yml config
```

#### 2. SSL Certificate Issues
```bash
# Check certificate status
make -f Makefile.production ssl-check

# Force renewal
make -f Makefile.production ssl-renew
```

#### 3. Database Connection Issues
```bash
# Test database connection
docker-compose -f docker-compose.production.yml exec postgres pg_isready

# Check PgBouncer
docker-compose -f docker-compose.production.yml logs pgbouncer
```

#### 4. High Memory Usage
```bash
# Check container stats
docker stats

# Adjust resource limits in docker-compose.production.yml
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
docker-compose -f docker-compose.production.yml up -d

# View debug logs
docker-compose -f docker-compose.production.yml logs -f junoscommander-1
```

## Performance Tuning

### PostgreSQL Optimization

Edit `postgres/postgresql.conf`:
```ini
# Adjust based on available RAM
shared_buffers = 512MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 128MB
```

### Redis Optimization

Edit `redis/redis.conf`:
```ini
# Adjust max memory
maxmemory 1gb
maxmemory-policy allkeys-lru
```

### Application Tuning

In `.env`:
```bash
# Connection pool settings
SSH_POOL_MAX_SIZE=200
DB_POOL_SIZE=50

# Worker settings
TASK_QUEUE_WORKERS=20
```

## Monitoring Alerts

Configure alerts in `monitoring/alert_rules.yml`:

```yaml
groups:
  - name: junoscommander
    rules:
      - alert: HighCPUUsage
        expr: rate(container_cpu_usage_seconds_total[5m]) > 0.8
        for: 5m
        annotations:
          summary: "High CPU usage detected"

      - alert: DatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        annotations:
          summary: "PostgreSQL is down"
```

## Backup Strategy

### Database Backups
- Daily automated backups at 2 AM
- 30-day retention policy
- Offsite backup to S3 (optional)

### Configuration Backups
```bash
# Backup all configurations
tar -czf configs_$(date +%Y%m%d).tar.gz .env traefik/ postgres/ redis/ monitoring/

# Store in version control or S3
aws s3 cp configs_$(date +%Y%m%d).tar.gz s3://junoscommander-backups/
```

## Disaster Recovery

### Recovery Time Objective (RTO): 30 minutes

1. **Restore from backup**:
```bash
# Restore database
make -f Makefile.production db-restore BACKUP=latest-backup.sql.gz

# Restore configurations
tar -xzf configs_latest.tar.gz

# Restart services
make -f Makefile.production up
```

2. **Verify recovery**:
```bash
make -f Makefile.production health-check
```

## Compliance

### Audit Logging
- All API calls logged with user, action, timestamp
- Logs retained for 90 days
- Exportable for compliance reporting

### Data Retention
- Task history: 90 days
- Audit logs: 1 year
- Device configurations: Indefinite

## Support

For issues or questions:
1. Check logs: `make -f Makefile.production logs`
2. Review documentation: `/docs` directory
3. GitHub Issues: https://github.com/yourusername/JunosCommander/issues

## Appendix

### A. Environment Variables Reference

See `.env.production` for complete list with descriptions.

### B. Port Reference

| Service | Internal Port | External Port |
|---------|--------------|---------------|
| Traefik | 80, 443, 8080 | 80, 443 |
| Application | 8080 | via Traefik |
| PostgreSQL | 5432 | none |
| PgBouncer | 6432 | none |
| Redis | 6379 | none |
| Prometheus | 9090 | 9091 |
| Grafana | 3000 | via Traefik |

### C. Network Reference

| Network | Subnet | Purpose |
|---------|--------|---------|
| proxy | 172.20.0.0/24 | External-facing services |
| backend | 172.21.0.0/24 | Application tier |
| database | 172.22.0.0/24 | Database tier |
| cache | 172.23.0.0/24 | Cache tier |
| monitoring | 172.24.0.0/24 | Monitoring stack |

### D. Useful Commands

```bash
# Container management
docker-compose -f docker-compose.production.yml ps
docker-compose -f docker-compose.production.yml exec <service> /bin/sh

# Database queries
docker-compose -f docker-compose.production.yml exec postgres psql -U junoscommander

# Redis CLI
docker-compose -f docker-compose.production.yml exec redis redis-cli

# View Traefik routes
docker-compose -f docker-compose.production.yml exec traefik wget -O - http://localhost:8080/api/http/routers
```