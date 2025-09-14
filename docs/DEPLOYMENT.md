# JunosCommander Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying JunosCommander in production environments.

## Deployment Methods

### 1. Docker Deployment (Recommended)

#### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- 10GB disk space

#### Production Configuration

Create `docker-compose.production.yml`:

```yaml
version: '3.8'

services:
  junoscommander:
    image: junoscommander:latest
    container_name: junoscommander
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - SERVER_MODE=production
      - DATABASE_TYPE=postgres
      - DATABASE_URL=${DATABASE_URL}
      - LDAP_HOST=${LDAP_HOST}
      - LDAP_BASE_DN=${LDAP_BASE_DN}
      - LDAP_BIND_DN=${LDAP_BIND_DN}
      - LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD}
      - SESSION_SECRET=${SESSION_SECRET}
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    networks:
      - junoscommander-net
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: junoscommander-db
    restart: unless-stopped
    environment:
      - POSTGRES_DB=junoscommander
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - junoscommander-net

networks:
  junoscommander-net:
    driver: bridge

volumes:
  postgres-data:
```

#### Deployment Steps

```bash
# 1. Create production directory
mkdir -p /opt/junoscommander
cd /opt/junoscommander

# 2. Create environment file
cat > .env <<EOF
DATABASE_URL=postgres://junoscommander:secure-password@postgres:5432/junoscommander?sslmode=require
LDAP_HOST=ldap://your-ldap.domain.com:389
LDAP_BASE_DN=dc=domain,dc=com
LDAP_BIND_DN=cn=service-account,dc=domain,dc=com
LDAP_BIND_PASSWORD=secure-bind-password
SESSION_SECRET=$(openssl rand -base64 32)
DB_USER=junoscommander
DB_PASSWORD=secure-db-password
EOF

# 3. Set permissions
chmod 600 .env

# 4. Pull and start services
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d

# 5. Verify deployment
docker-compose -f docker-compose.production.yml ps
curl http://localhost:8080/health
```

### 2. Kubernetes Deployment

#### Prerequisites
- Kubernetes 1.24+
- kubectl configured
- Helm 3.0+ (optional)

#### Kubernetes Manifests

Create namespace:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: junoscommander
```

ConfigMap:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: junoscommander-config
  namespace: junoscommander
data:
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "8080"
  SERVER_MODE: "production"
  DATABASE_TYPE: "postgres"
  LOG_LEVEL: "info"
```

Secret:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: junoscommander-secret
  namespace: junoscommander
type: Opaque
stringData:
  DATABASE_URL: "postgres://user:pass@postgres:5432/junoscommander"
  LDAP_BIND_PASSWORD: "your-ldap-password"
  SESSION_SECRET: "your-session-secret"
```

Deployment:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: junoscommander
  namespace: junoscommander
spec:
  replicas: 3
  selector:
    matchLabels:
      app: junoscommander
  template:
    metadata:
      labels:
        app: junoscommander
    spec:
      containers:
      - name: junoscommander
        image: junoscommander:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: junoscommander-config
        - secretRef:
            name: junoscommander-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

Service:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: junoscommander
  namespace: junoscommander
spec:
  selector:
    app: junoscommander
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

#### Deploy to Kubernetes

```bash
# Apply manifests
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Check status
kubectl get all -n junoscommander

# Get external IP
kubectl get svc junoscommander -n junoscommander
```

### 3. Systemd Service (Bare Metal)

#### Installation

```bash
# 1. Create application directory
sudo mkdir -p /opt/junoscommander
sudo chown $USER:$USER /opt/junoscommander

# 2. Copy binary
sudo cp bin/junoscommander /opt/junoscommander/

# 3. Create systemd service
sudo cat > /etc/systemd/system/junoscommander.service <<EOF
[Unit]
Description=JunosCommander Network Automation Platform
After=network.target

[Service]
Type=simple
User=junoscommander
Group=junoscommander
WorkingDirectory=/opt/junoscommander
ExecStart=/opt/junoscommander/junoscommander
Restart=always
RestartSec=10
StandardOutput=append:/var/log/junoscommander/app.log
StandardError=append:/var/log/junoscommander/error.log
Environment="SERVER_MODE=production"
EnvironmentFile=/opt/junoscommander/.env

[Install]
WantedBy=multi-user.target
EOF

# 4. Create user and directories
sudo useradd -r -s /bin/false junoscommander
sudo mkdir -p /var/log/junoscommander
sudo chown junoscommander:junoscommander /var/log/junoscommander

# 5. Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable junoscommander
sudo systemctl start junoscommander

# 6. Check status
sudo systemctl status junoscommander
```

## High Availability Setup

### Load Balancer Configuration

#### Nginx
```nginx
upstream junoscommander {
    least_conn;
    server app1.internal:8080 max_fails=3 fail_timeout=30s;
    server app2.internal:8080 max_fails=3 fail_timeout=30s;
    server app3.internal:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name junoscommander.domain.com;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    location / {
        proxy_pass http://junoscommander;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /health {
        access_log off;
        proxy_pass http://junoscommander/health;
    }
}
```

#### HAProxy
```haproxy
global
    maxconn 4096
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend junoscommander_frontend
    bind *:443 ssl crt /etc/haproxy/certs/junoscommander.pem
    redirect scheme https if !{ ssl_fc }
    default_backend junoscommander_backend

backend junoscommander_backend
    balance leastconn
    option httpchk GET /health
    server app1 app1.internal:8080 check
    server app2 app2.internal:8080 check
    server app3 app3.internal:8080 check
```

### Database High Availability

#### PostgreSQL Replication

Primary configuration:
```ini
# postgresql.conf
wal_level = replica
max_wal_senders = 3
wal_keep_segments = 64
synchronous_commit = on
synchronous_standby_names = 'standby1,standby2'
```

Standby configuration:
```ini
# recovery.conf
standby_mode = on
primary_conninfo = 'host=primary port=5432 user=replicator'
trigger_file = '/tmp/postgresql.trigger'
```

## Security Hardening

### SSL/TLS Configuration

Generate certificates:
```bash
# Self-signed certificate (development)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt

# Let's Encrypt (production)
certbot certonly --standalone -d junoscommander.domain.com
```

Update configuration:
```env
SERVER_TLS_ENABLED=true
SERVER_TLS_CERT=/path/to/cert.pem
SERVER_TLS_KEY=/path/to/key.pem
```

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 8080/tcp # Application (internal only)
sudo ufw enable
```

### Security Checklist

- [ ] Change default passwords
- [ ] Enable TLS/SSL
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up log rotation
- [ ] Configure rate limiting
- [ ] Enable CORS restrictions
- [ ] Set secure session timeout
- [ ] Configure IP allowlisting
- [ ] Enable database encryption
- [ ] Set up backup encryption
- [ ] Configure intrusion detection

## Monitoring

### Prometheus Configuration

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'junoscommander'
    static_configs:
      - targets: ['junoscommander:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import dashboard JSON from `monitoring/grafana-dashboard.json`

Key metrics to monitor:
- HTTP request rate and latency
- Active SSH connections
- Task execution time
- Error rates
- Database connection pool
- Memory and CPU usage

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/junoscommander"

# PostgreSQL backup
pg_dump -h postgres -U junoscommander junoscommander | \
  gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Retain last 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

### Application Backup

```bash
# Backup configuration and logs
tar -czf backup_config_$DATE.tar.gz \
  /opt/junoscommander/.env \
  /opt/junoscommander/logs/
```

### Disaster Recovery

1. **Database Recovery**:
```bash
gunzip < backup.sql.gz | psql -h postgres -U junoscommander junoscommander
```

2. **Application Recovery**:
```bash
docker-compose -f docker-compose.production.yml down
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d
```

## Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check logs
docker logs junoscommander
journalctl -u junoscommander -f

# Verify configuration
docker exec junoscommander env | grep -E "LDAP|DATABASE"
```

#### Database Connection Issues
```bash
# Test connection
docker exec junoscommander pg_isready -h postgres -U junoscommander

# Check PostgreSQL logs
docker logs junoscommander-db
```

#### LDAP Authentication Failures
```bash
# Test LDAP connection
ldapsearch -x -H ldap://ldap.domain.com \
  -D "cn=admin,dc=domain,dc=com" -W \
  -b "dc=domain,dc=com" "(uid=testuser)"
```

### Performance Tuning

#### Application Tuning
```env
# Increase worker pool for high load
TASK_WORKER_POOL_SIZE=20
SSH_POOL_SIZE=100
DATABASE_MAX_CONNECTIONS=50
```

#### Database Tuning
```sql
-- PostgreSQL optimization
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
```

## Maintenance

### Regular Tasks

- **Daily**: Check logs for errors, monitor disk space
- **Weekly**: Review performance metrics, test backups
- **Monthly**: Update dependencies, security patches
- **Quarterly**: Disaster recovery drill, capacity planning

### Upgrade Procedure

```bash
# 1. Backup current version
docker save junoscommander:latest > junoscommander_backup.tar

# 2. Pull new version
docker pull junoscommander:v1.1.0

# 3. Test in staging
docker-compose -f docker-compose.staging.yml up -d

# 4. Rolling update in production
docker-compose -f docker-compose.production.yml up -d --no-deps --scale junoscommander=2 junoscommander

# 5. Verify and complete
docker-compose -f docker-compose.production.yml ps
```

## Support

For support:
- Email: seaverb@icloud.com
- GitHub Issues: https://github.com/brndnsvr/JunosCommander

---

**Document Version:** 1.0.0
**Last Updated:** September 2024