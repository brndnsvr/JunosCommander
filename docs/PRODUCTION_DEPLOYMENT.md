# JunosCommander Production Deployment Guide

## Architecture Overview

The production deployment of JunosCommander uses a comprehensive multi-container architecture designed for security, scalability, and observability.

### Key Components

1. **Traefik** - Reverse proxy with automatic HTTPS/Let's Encrypt
2. **PostgreSQL** - Production database with replication support
3. **Redis** - Session management and caching layer
4. **Prometheus/Grafana** - Metrics and visualization
5. **Loki/Promtail** - Log aggregation
6. **Jaeger** - Distributed tracing
7. **HashiCorp Vault** - Secrets management
8. **Application Instances** - Multiple instances for HA

### Network Architecture

```
Internet
    │
    ├─── Traefik (80/443) ─── SSL Termination
    │         │
    │    ┌────┴────┐
    │    │  Proxy  │ (172.20.0.0/24)
    │    └────┬────┘
    │         │
    ├─────────┼─── App Instance 1 ─┐
    │         │                     │
    ├─────────┼─── App Instance 2 ─┤
    │         │                     │
    │    ┌────┴────┐               │
    │    │ Backend │ (172.21.0.0/24)
    │    └────┬────┘               │
    │         │                     │
    │    ┌────┴────┐               │
    │    │Database │ (172.22.0.0/24)
    │    └────┬────┘               │
    │         ├─── PostgreSQL       │
    │         │                     │
    │    ┌────┴────┐               │
    │    │  Cache  │ (172.23.0.0/24)
    │    └────┬────┘               │
    │         ├─── Redis            │
    │         │                     │
    │    ┌────┴────┐               │
    │    │Monitoring│ (172.24.0.0/24)
    │    └─────────┘               │
    │         ├─── Prometheus       │
    │         ├─── Grafana          │
    │         ├─── Loki             │
    │         └─── Jaeger           │
    │                               │
    └───────────────────────────────┘
```

## Security Features

### 1. Network Segmentation
- **Proxy Network**: External-facing services only
- **Backend Network**: Internal application communication
- **Database Network**: Isolated database access
- **Cache Network**: Isolated Redis access
- **Monitoring Network**: Metrics and logs collection

### 2. TLS/SSL
- Automatic HTTPS via Let's Encrypt
- TLS 1.2+ enforcement
- Strong cipher suites only
- HSTS headers with preload

### 3. Authentication & Authorization
- AD/LDAP integration for user authentication
- Service-to-service mTLS support
- Session encryption with AES-256-GCM
- JWT tokens for API access

### 4. Security Headers
- Content Security Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict referrer policy

### 5. Rate Limiting
- 100 requests/minute average
- 200 request burst capacity
- IP-based throttling

## Deployment Steps

### Prerequisites

1. **Server Requirements**
   - Docker 24.0+
   - Docker Compose 2.20+
   - 8GB RAM minimum (16GB recommended)
   - 50GB disk space
   - Ubuntu 22.04 LTS or RHEL 9

2. **Network Requirements**
   - Public IP address
   - Ports 80/443 open for HTTP/HTTPS
   - Domain name with DNS configured

3. **External Services**
   - Active Directory/LDAP server
   - SMTP server for alerts (optional)
   - S3-compatible storage for backups (optional)

### Step 1: Initial Setup

```bash
# Clone repository
git clone https://github.com/your-org/junoscommander.git
cd junoscommander

# Initialize production environment
make -f Makefile.production init

# Copy and configure environment
cp .env.production.example .env.production
nano .env.production
```

### Step 2: Configure Environment

Edit `.env.production` with your values:

```bash
# Required configurations
DOMAIN=junoscommander.yourcompany.com
DB_PASSWORD=<generate-secure-password>
REDIS_PASSWORD=<generate-secure-password>
SESSION_KEY=<generate-32-byte-key>
JWT_SECRET=<generate-64-byte-secret>
AD_SERVER=ldaps://your-ad.company.com
AD_SERVICE_USER=svc_junoscommander@company.com
AD_SERVICE_PASSWORD=<service-account-password>
```

Generate secure secrets:
```bash
make -f Makefile.production generate-secrets
```

### Step 3: Configure SSL/TLS

#### Option A: Let's Encrypt HTTP Challenge
```yaml
# .env.production
ACME_EMAIL=admin@yourcompany.com
```

#### Option B: Let's Encrypt DNS Challenge (Cloudflare)
```yaml
# .env.production
CLOUDFLARE_EMAIL=admin@yourcompany.com
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
```

### Step 4: Deploy Application

```bash
# Build images
make -f Makefile.production build

# Start services
make -f Makefile.production up

# Check health
make -f Makefile.production health
```

### Step 5: Initialize Database

```bash
# Run migrations
make -f Makefile.production db-migrate

# Import initial data (if needed)
docker exec -i junoscommander-postgres psql -U junoscommander < initial_data.sql
```

### Step 6: Configure Monitoring

Access monitoring dashboards:
- Grafana: https://grafana.junoscommander.yourcompany.com
- Prometheus: https://prometheus.junoscommander.yourcompany.com
- Jaeger: https://jaeger.junoscommander.yourcompany.com

Default Grafana credentials:
- Username: admin
- Password: (from .env.production)

## Scaling Configuration

### Horizontal Scaling

Scale application instances:
```bash
# Scale to 3 instances
make -f Makefile.production scale-up

# Scale back to 1 instance
make -f Makefile.production scale-down
```

### Database Scaling

For high-load environments, configure PostgreSQL replication:

```yaml
# docker-compose.production.yml addition
postgres-replica:
  image: postgres:16-alpine
  environment:
    - POSTGRES_REPLICATION_MODE=slave
    - POSTGRES_MASTER_HOST=postgres
    - POSTGRES_REPLICATION_USER=replicator
    - POSTGRES_REPLICATION_PASSWORD=${REPLICATION_PASSWORD}
```

### Redis Clustering

For session high availability, enable Redis Sentinel:
```bash
# Already configured in docker-compose.production.yml
# Redis Sentinel monitors and provides automatic failover
```

## Backup & Recovery

### Automated Backups

Configure automated backups in `.env.production`:
```bash
BACKUP_RETENTION_DAYS=30
BACKUP_SCHEDULE="0 2 * * *"  # 2 AM daily
```

### Manual Backup

```bash
# Full backup
make -f Makefile.production backup-all

# Database only
make -f Makefile.production db-backup
```

### Restore from Backup

```bash
# Restore database
make -f Makefile.production db-restore BACKUP_FILE=./backups/postgres/backup_20240114.sql.gz
```

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Application Metrics**
   - Request rate and latency
   - Error rate (4xx, 5xx)
   - Active SSH connections
   - Task execution time

2. **Infrastructure Metrics**
   - CPU and memory usage
   - Disk I/O and space
   - Network throughput
   - Container health

3. **Database Metrics**
   - Connection pool usage
   - Query performance
   - Replication lag
   - Lock statistics

### Alert Configuration

Configure alerts in `./alertmanager/config.yml`:
```yaml
receivers:
  - name: 'ops-team'
    slack_configs:
      - api_url: ${SLACK_WEBHOOK_URL}
        channel: '#ops-alerts'
    email_configs:
      - to: 'ops-team@company.com'
        from: 'alerts@junoscommander.com'
```

## Maintenance

### Regular Updates

```bash
# Update all services
make -f Makefile.production update

# Update specific service
docker-compose -f docker-compose.production.yml pull grafana
docker-compose -f docker-compose.production.yml up -d grafana
```

### Log Rotation

Logs are automatically rotated with:
- Max size: 10MB per file
- Keep 3 rotated files
- JSON format for structured logging

### Database Maintenance

```bash
# Vacuum and analyze
docker exec junoscommander-postgres psql -U junoscommander -c "VACUUM ANALYZE;"

# Reindex
docker exec junoscommander-postgres psql -U junoscommander -c "REINDEX DATABASE junoscommander;"
```

## Troubleshooting

### Common Issues

1. **Cannot connect to AD/LDAP**
   ```bash
   # Check connectivity
   docker exec junoscommander-app-1 nc -zv your-ad.company.com 636

   # Verify credentials
   docker exec junoscommander-app-1 ldapsearch -x -H ldaps://your-ad.company.com \
     -D "svc_junoscommander@company.com" -W
   ```

2. **Database connection issues**
   ```bash
   # Check PostgreSQL status
   docker exec junoscommander-postgres pg_isready

   # View PostgreSQL logs
   docker logs junoscommander-postgres --tail 50
   ```

3. **High memory usage**
   ```bash
   # Check container stats
   docker stats --no-stream

   # Adjust memory limits in docker-compose.production.yml
   ```

### Debug Mode

Enable debug logging:
```bash
# Enable debug mode
make -f Makefile.production debug

# View debug logs
docker logs junoscommander-app-1 -f | grep DEBUG
```

### Container Shell Access

```bash
# Application shell
make -f Makefile.production shell

# Database shell
make -f Makefile.production db-shell

# Redis CLI
make -f Makefile.production redis-cli
```

## Security Hardening

### 1. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 10.0.0.0/8 to any port 22
sudo ufw enable
```

### 2. SELinux/AppArmor

```bash
# For RHEL/CentOS
sudo setsebool -P container_manage_cgroup on

# For Ubuntu
sudo aa-complain /etc/apparmor.d/docker
```

### 3. Docker Security

```bash
# Run Docker daemon with security options
# /etc/docker/daemon.json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userland-proxy": false,
  "live-restore": true,
  "seccomp-profile": "/etc/docker/seccomp.json"
}
```

### 4. Regular Security Scans

```bash
# Scan images for vulnerabilities
make -f Makefile.production security-scan

# Audit Docker configuration
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  docker/docker-bench-security
```

## Performance Tuning

### 1. PostgreSQL Optimization

```sql
-- postgresql.conf
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 10MB
maintenance_work_mem = 512MB
max_connections = 200
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
```

### 2. Redis Optimization

```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
tcp-backlog 511
tcp-keepalive 300
save ""  # Disable persistence for cache-only use
```

### 3. Application Tuning

```yaml
# Environment variables
TASK_WORKER_POOL_SIZE: 100
SSH_MAX_CONNECTIONS: 200
DB_POOL_SIZE: 50
```

## Compliance & Auditing

### Audit Logging

All actions are logged with:
- User identification
- Timestamp
- Action performed
- Target device
- Result status

### Compliance Reports

Generate compliance reports:
```bash
# Export audit logs
docker exec junoscommander-postgres psql -U junoscommander \
  -c "COPY audit_logs TO '/tmp/audit_logs.csv' CSV HEADER;"

# Generate report
docker exec junoscommander-app-1 ./junoscommander report --type compliance
```

### Data Retention

Configure retention policies:
```yaml
# .env.production
AUDIT_LOG_RETENTION_DAYS=365
TASK_LOG_RETENTION_DAYS=90
SESSION_LOG_RETENTION_DAYS=30
```

## Disaster Recovery

### RTO/RPO Targets

- **RTO** (Recovery Time Objective): 1 hour
- **RPO** (Recovery Point Objective): 1 hour

### DR Procedures

1. **Database Failure**
   - Automatic failover to replica (if configured)
   - Restore from hourly backup
   - Estimated recovery: 15 minutes

2. **Application Failure**
   - Automatic container restart
   - Load balancer health checks
   - Estimated recovery: < 1 minute

3. **Complete System Failure**
   - Deploy to standby environment
   - Restore database from backup
   - Update DNS records
   - Estimated recovery: 45 minutes

## Support & Resources

- Issue Tracker: https://github.com/brndnsvr/JunosCommander/issues
- Contact: dev@brndnsvr.com
- Documentation: See README and docs/ directory