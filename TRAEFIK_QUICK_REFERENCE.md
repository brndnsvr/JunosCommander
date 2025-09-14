# JunosCommander + Traefik Quick Reference

## 🚀 Quick Deployment

```bash
# 1. Configure environment
cp .env.traefik .env
# Edit .env with your domains and settings

# 2. Deploy
make traefik-deploy
# OR
./scripts/deploy-traefik.sh deploy

# 3. Check status
make traefik-status
```

## 📋 Essential Commands

### Deployment Management
```bash
make traefik-deploy          # Full deployment
make traefik-start           # Start services
make traefik-stop            # Stop services
make traefik-restart         # Restart services
make traefik-status          # Show status
make traefik-cleanup         # Complete cleanup
```

### Monitoring & Logs
```bash
make traefik-logs            # Traefik logs
make traefik-app-logs        # Application logs
make traefik-all-logs        # All service logs
make health-check            # Service health
```

### Configuration
```bash
make traefik-config          # Validate config
make traefik-genpass PASS=secret  # Generate password
make env-template            # Setup environment
```

## 🔧 Key Configuration Files

| File | Purpose |
|------|---------|
| `traefik/traefik.yml` | Main Traefik configuration |
| `traefik/dynamic/security.yml` | Security middleware & routing |
| `traefik/dynamic/tls.yml` | TLS/SSL settings |
| `docker-compose.traefik.yml` | Production compose file |
| `.env.traefik` | Environment template |

## 🌐 Default Service URLs

Replace `example.com` with your actual domain:

- **JunosCommander**: `https://jc.example.com`
- **Traefik Dashboard**: `https://traefik.example.com/dashboard/`
- **LDAP Admin**: `https://ldap-admin.example.com`
- **Prometheus**: `https://prometheus.example.com`
- **Grafana**: `https://grafana.example.com`

## 🔒 Security Features

- ✅ **Automatic HTTPS** with Let's Encrypt
- ✅ **Security Headers** (HSTS, CSP, XSS protection)
- ✅ **Rate Limiting** (API: 50/min, Auth: 5/min)
- ✅ **DDoS Protection** (100/min baseline)
- ✅ **Circuit Breakers** (30% error threshold)
- ✅ **WebSocket Support** for real-time updates
- ✅ **IP Whitelisting** for dashboards

## ⚡ Performance Features

- ✅ **HTTP/2** support with ALPN
- ✅ **Response Compression** (gzip/brotli)
- ✅ **Connection Pooling** optimized
- ✅ **Health Checks** (30s interval)
- ✅ **Load Balancing** ready
- ✅ **Retry Logic** (3 attempts)

## 🚨 Common Issues & Solutions

### Certificate Problems
```bash
# Check certificate status
docker compose -f docker-compose.traefik.yml logs traefik | grep -i acme

# Reset certificates
rm traefik/certificates/acme.json
touch traefik/certificates/acme.json
chmod 600 traefik/certificates/acme.json
```

### Service Not Accessible
```bash
# Check internal connectivity
docker exec junoscommander-traefik curl -I http://junoscommander:8080/health

# Verify DNS
nslookup your-domain.com

# Test rate limiting
curl -I https://your-domain.com/api/test
```

### High Resource Usage
```bash
# Check container stats
docker stats

# Monitor metrics
curl http://localhost:8080/metrics | grep traefik_service

# Review access patterns
tail -f logs/traefik/access.log | jq '.'
```

## 📊 Monitoring Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/metrics` | Prometheus metrics |
| `/ping` | Health check |
| `/dashboard/` | Traefik dashboard |
| `/health` | Application health |

## 🔍 SSL Certificate Commands

```bash
# Test SSL configuration
make ssl-test DOMAIN=your-domain.com

# Check certificate expiration
make ssl-check DOMAIN=your-domain.com

# SSL Labs test URL
echo "https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com"
```

## 📝 Environment Variables (Critical)

```bash
# Core Configuration (.env file)
JUNOSCOMMANDER_DOMAIN=jc.yourdomain.com
TRAEFIK_DOMAIN=traefik.yourdomain.com
LETSENCRYPT_EMAIL=admin@yourdomain.com

# Security
TRAEFIK_DASHBOARD_USERS=admin:$2y$10$...  # htpasswd hash

# Rate Limiting
API_RATE_LIMIT_AVERAGE=50
AUTH_RATE_LIMIT_AVERAGE=5
DDOS_RATE_LIMIT_AVERAGE=100
```

## 🎯 Production Checklist

### Pre-Deployment
- [ ] DNS records configured and propagated
- [ ] Domain names updated in .env
- [ ] Let's Encrypt email configured
- [ ] Dashboard password generated
- [ ] Firewall allows ports 80, 443
- [ ] SSL/TLS settings reviewed

### Post-Deployment
- [ ] All services show "healthy" status
- [ ] HTTPS certificates issued successfully
- [ ] HTTP→HTTPS redirects working
- [ ] API endpoints responding
- [ ] WebSocket connections functional
- [ ] Dashboard accessible with auth
- [ ] Rate limiting tested
- [ ] Monitoring data flowing

### Ongoing Maintenance
- [ ] Certificate auto-renewal working
- [ ] Log rotation configured
- [ ] Backup strategy implemented
- [ ] Security scanning scheduled
- [ ] Performance monitoring active
- [ ] Alert thresholds configured

## 🆘 Emergency Procedures

### Service Down
```bash
# Quick restart
make traefik-restart

# Emergency fallback to basic setup
docker compose up -d junoscommander
```

### Certificate Emergency
```bash
# Temporary self-signed (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 1

# Switch to HTTP temporarily (edit traefik.yml)
# Comment out certificateResolvers section
```

### Rate Limit Emergency
```bash
# Temporarily disable rate limiting
# Edit traefik/dynamic/security.yml
# Comment out rate limit middleware
make traefik-restart
```

## 📞 Getting Help

1. **Logs**: `make traefik-logs` or `make traefik-all-logs`
2. **Status**: `make traefik-status` and `make health-check`
3. **Config**: `make traefik-config` to validate
4. **Docs**: See `docs/TRAEFIK_DEPLOYMENT.md` for detailed guide
5. **Community**: Traefik community forum and documentation

---

**Pro Tip**: Always test configuration changes in a staging environment first!