# JunosCommander Traefik Deployment Guide

This guide provides comprehensive instructions for deploying JunosCommander with Traefik reverse proxy in production environments.

## Overview

The Traefik configuration provides:

- **Automatic HTTPS** with Let's Encrypt certificate management
- **Security hardening** with comprehensive security headers and CSP
- **Rate limiting** and DDoS protection
- **WebSocket support** for real-time updates
- **Monitoring integration** with Prometheus metrics
- **Production-ready** configuration with proper timeouts and circuit breakers

## Prerequisites

- Docker and Docker Compose v2+
- Domain names with DNS configured
- Firewall configured to allow ports 80, 443
- Valid email address for Let's Encrypt notifications

## Quick Start

1. **Clone and navigate to project directory:**
   ```bash
   cd JunosCommander
   ```

2. **Configure environment:**
   ```bash
   cp .env.traefik .env
   # Edit .env with your domain names and configuration
   ```

3. **Deploy with Traefik:**
   ```bash
   ./scripts/deploy-traefik.sh deploy
   ```

4. **Check status:**
   ```bash
   ./scripts/deploy-traefik.sh status
   ```

## Configuration Files

### Core Configuration

- **`traefik/traefik.yml`** - Main Traefik static configuration
- **`traefik/dynamic/security.yml`** - Security middleware and routing
- **`traefik/dynamic/tls.yml`** - TLS/SSL configuration
- **`docker-compose.traefik.yml`** - Production Docker Compose with Traefik
- **`.env.traefik`** - Environment variables template

### Supporting Files

- **`monitoring/prometheus.yml`** - Prometheus monitoring configuration
- **`scripts/deploy-traefik.sh`** - Automated deployment script

## Domain Configuration

Update these domains in your `.env` file:

```bash
# Primary domains (CHANGE THESE!)
TRAEFIK_DOMAIN=traefik.yourdomain.com
JUNOSCOMMANDER_DOMAIN=jc.yourdomain.com
JUNOSCOMMANDER_ALT_DOMAIN=junoscommander.yourdomain.com

# Management interfaces
LDAP_ADMIN_DOMAIN=ldap-admin.yourdomain.com
PROMETHEUS_DOMAIN=prometheus.yourdomain.com
GRAFANA_DOMAIN=grafana.yourdomain.com

# Let's Encrypt
LETSENCRYPT_EMAIL=admin@yourdomain.com
```

### DNS Configuration

Configure DNS A records pointing to your server:

```
jc.yourdomain.com                    IN A    YOUR_SERVER_IP
junoscommander.yourdomain.com        IN A    YOUR_SERVER_IP
traefik.yourdomain.com               IN A    YOUR_SERVER_IP
ldap-admin.yourdomain.com            IN A    YOUR_SERVER_IP
prometheus.yourdomain.com            IN A    YOUR_SERVER_IP
grafana.yourdomain.com               IN A    YOUR_SERVER_IP
```

## Security Features

### Authentication & Authorization

The configuration includes multiple layers of authentication:

1. **Dashboard Access Control:**
   - Basic authentication for Traefik dashboard
   - IP whitelisting for management interfaces
   - Rate limiting on authentication endpoints

2. **Application Security:**
   - Session-based authentication for JunosCommander
   - LDAP/AD integration
   - JWT token validation

### Security Headers

Comprehensive security headers are automatically applied:

```yaml
# Content Security Policy
CSP: "default-src 'self'; script-src 'self' 'unsafe-inline'"

# Security Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
```

### Rate Limiting

Different rate limits for different endpoints:

- **API endpoints:** 50 requests/minute, burst 100
- **Authentication:** 5 requests/minute, burst 10
- **General access:** 100 requests/minute, burst 200

### TLS Configuration

Strong TLS configuration with:

- **TLS 1.2+ only** (configurable down to TLS 1.0 for legacy clients)
- **Strong cipher suites** prioritizing ECDHE and AES-GCM
- **HTTP/2 support** with ALPN
- **Perfect Forward Secrecy**

## Certificate Management

### Automatic Let's Encrypt

The configuration uses HTTP-01 challenge by default:

```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      email: your-email@domain.com
      storage: /certificates/acme.json
      httpChallenge:
        entryPoint: web
```

### DNS-01 Challenge (Optional)

For wildcard certificates, configure DNS-01 challenge:

```yaml
# Uncomment in traefik.yml and configure provider
dnsChallenge:
  provider: cloudflare  # or your DNS provider
  delayBeforeCheck: 0
  resolvers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
```

Supported providers: Cloudflare, AWS Route53, Google Cloud DNS, Azure DNS, and many more.

## Monitoring & Observability

### Prometheus Metrics

Traefik automatically exposes metrics at `/metrics`:

- Request duration and count
- Response status codes
- Backend health status
- Certificate expiration dates

### Access Logs

Comprehensive access logging in JSON format:

```json
{
  \"time\": \"2024-01-01T12:00:00Z\",
  \"remoteAddr\": \"1.2.3.4:12345\",
  \"method\": \"GET\",
  \"url\": \"/api/devices\",
  \"protocol\": \"HTTP/2.0\",
  \"status\": 200,
  \"size\": 1234,
  \"duration\": 45,
  \"userAgent\": \"Mozilla/5.0...\"
}
```

### Health Checks

All services include health checks:

- **Application:** `/health` endpoint
- **Database:** Connection test
- **LDAP:** Directory search test
- **Traefik:** Built-in ping endpoint

## High Availability Features

### Circuit Breakers

Automatic circuit breaker protection:

```yaml
circuitBreaker:
  expression: "NetworkErrorRatio() > 0.30 || ResponseCodeRatio(500, 600, 0, 600) > 0.25"
  checkPeriod: "10s"
  fallbackDuration: "30s"
```

### Retry Logic

Automatic retry for transient failures:

```yaml
retry:
  attempts: 3
  initialInterval: "100ms"
```

### Load Balancing

Ready for multiple backend instances:

```yaml
loadBalancer:
  servers:
    - url: "http://junoscommander-1:8080"
    - url: "http://junoscommander-2:8080"
  healthCheck:
    path: "/health"
    interval: "30s"
```

## Performance Optimizations

### Compression

Automatic response compression for:
- HTML, CSS, JavaScript
- JSON and XML responses
- Text-based content

### HTTP/2 Support

Full HTTP/2 support with:
- Server push capabilities
- Stream multiplexing
- Header compression

### Connection Pooling

Optimized backend connections:
- Connection reuse
- Configurable timeouts
- Keep-alive settings

## Deployment Commands

### Basic Operations

```bash
# Deploy (full setup)
./scripts/deploy-traefik.sh deploy

# Start services
./scripts/deploy-traefik.sh start

# Stop services
./scripts/deploy-traefik.sh stop

# Restart services
./scripts/deploy-traefik.sh restart

# Check status
./scripts/deploy-traefik.sh status

# View logs
./scripts/deploy-traefik.sh logs [service-name]
```

### Advanced Operations

```bash
# Generate password hash for dashboard
./scripts/deploy-traefik.sh genpass your-secure-password

# Complete cleanup (removes volumes)
./scripts/deploy-traefik.sh cleanup

# Manual Docker Compose operations
docker compose -f docker-compose.traefik.yml up -d
docker compose -f docker-compose.traefik.yml ps
docker compose -f docker-compose.traefik.yml logs traefik
```

## Troubleshooting

### Common Issues

#### Certificate Issues

1. **Certificate not issued:**
   ```bash
   # Check Traefik logs
   docker compose -f docker-compose.traefik.yml logs traefik | grep -i acme

   # Verify domain DNS
   nslookup your-domain.com

   # Test HTTP-01 challenge access
   curl -I http://your-domain.com/.well-known/acme-challenge/test
   ```

2. **Certificate renewal failure:**
   ```bash
   # Check certificate storage
   ls -la traefik/certificates/

   # Reset certificates (if needed)
   rm traefik/certificates/acme.json
   touch traefik/certificates/acme.json
   chmod 600 traefik/certificates/acme.json
   ```

#### Connectivity Issues

1. **Service unreachable:**
   ```bash
   # Check service health
   docker compose -f docker-compose.traefik.yml ps

   # Test internal connectivity
   docker exec junoscommander-traefik curl -I http://junoscommander:8080/health

   # Check DNS resolution
   docker exec junoscommander-traefik nslookup junoscommander
   ```

2. **Rate limiting triggered:**
   ```bash
   # Check access logs
   tail -f logs/traefik/access.log | jq '.status'

   # Temporarily disable rate limiting (edit security.yml)
   # Restart Traefik to apply changes
   docker compose -f docker-compose.traefik.yml restart traefik
   ```

#### Performance Issues

1. **Slow response times:**
   ```bash
   # Check backend health
   curl -I http://localhost:8080/health

   # Monitor Traefik metrics
   curl http://localhost:8080/metrics | grep traefik_service_request_duration

   # Check resource usage
   docker stats
   ```

### Logging and Debugging

#### Enable Debug Logging

Update `traefik.yml`:

```yaml
log:
  level: DEBUG  # Change from INFO
```

#### View Structured Logs

```bash
# Pretty-print JSON logs
docker compose -f docker-compose.traefik.yml logs traefik | jq '.'

# Filter specific log levels
docker compose -f docker-compose.traefik.yml logs traefik | jq 'select(.level=="ERROR")'

# Monitor access logs
tail -f logs/traefik/access.log | jq 'select(.status >= 400)'
```

## Production Checklist

### Pre-deployment

- [ ] DNS records configured and propagated
- [ ] Firewall rules allow ports 80, 443
- [ ] Domain names updated in configuration
- [ ] Let's Encrypt email configured
- [ ] Dashboard authentication configured
- [ ] SSL/TLS settings reviewed
- [ ] Rate limiting configured appropriately
- [ ] Monitoring endpoints accessible

### Post-deployment

- [ ] All services healthy and running
- [ ] Certificates issued successfully
- [ ] HTTPS redirects working
- [ ] WebSocket connections functional
- [ ] API endpoints responding correctly
- [ ] Dashboard accessible with authentication
- [ ] Monitoring data flowing to Prometheus
- [ ] Log rotation configured
- [ ] Backup strategy implemented

### Security Validation

- [ ] SSL Labs test: A+ rating
- [ ] Security headers validation
- [ ] Rate limiting tested
- [ ] Authentication mechanisms verified
- [ ] Access logs reviewed
- [ ] Vulnerability scanning performed

## Maintenance

### Regular Tasks

1. **Monitor certificate expiration:**
   ```bash
   # Check certificate status
   curl -I https://your-domain.com | grep -i expire

   # View Traefik certificate info
   docker exec junoscommander-traefik cat /certificates/acme.json | jq '.letsencrypt.Certificates[].domain'
   ```

2. **Review access logs:**
   ```bash
   # Check for suspicious activity
   grep -E "(401|403|404|429|5[0-9]{2})" logs/traefik/access.log

   # Monitor rate limiting
   grep -E "429" logs/traefik/access.log | tail -20
   ```

3. **Update configurations:**
   ```bash
   # Apply configuration changes
   docker compose -f docker-compose.traefik.yml restart traefik

   # Verify configuration
   docker compose -f docker-compose.traefik.yml config
   ```

### Backup Strategy

```bash
# Backup certificates
tar -czf certificates-backup-$(date +%Y%m%d).tar.gz traefik/certificates/

# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz traefik/ .env

# Backup application data
tar -czf data-backup-$(date +%Y%m%d).tar.gz data/
```

## Support

For additional support:

1. Review Traefik documentation: https://doc.traefik.io/traefik/
2. Check JunosCommander logs for application-specific issues
3. Validate network connectivity and DNS resolution
4. Test certificate renewal process in staging environment
5. Monitor resource usage and performance metrics

## Security Considerations

### Production Security Hardening

1. **Network Security:**
   - Use private networks for backend services
   - Implement IP whitelisting for management interfaces
   - Configure firewalls to restrict access

2. **Authentication:**
   - Use strong passwords and consider 2FA
   - Implement OAuth/OIDC instead of basic auth for dashboards
   - Regular credential rotation

3. **Monitoring:**
   - Set up alerts for certificate expiration
   - Monitor for unusual traffic patterns
   - Log aggregation and analysis

4. **Updates:**
   - Regular security updates for all components
   - Automated vulnerability scanning
   - Security patch management process