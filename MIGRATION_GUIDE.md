# JunosCommander Database Migration Guide

This guide provides step-by-step instructions for migrating JunosCommander from SQLite development database to PostgreSQL production environment with Redis caching.

## Overview

The production database architecture includes:
- **PostgreSQL 15**: Primary database optimized for 1000+ network devices
- **Redis 7**: Session storage and caching layer
- **PgBouncer**: Connection pooling for high concurrency
- **Automated backups**: Full, incremental, and schema-only backups
- **Health monitoring**: Comprehensive database monitoring and alerting

## Prerequisites

Before starting the migration, ensure you have:

### Software Requirements
- Docker and Docker Compose
- Python 3.8+ with pip
- PostgreSQL client tools (`psql`, `pg_dump`)
- Access to your current SQLite database

### Infrastructure Requirements
- Sufficient disk space for database migration and backups
- Network access to PostgreSQL and Redis services
- Appropriate system resources (see resource requirements below)

### Resource Requirements

| Service | CPU | Memory | Storage |
|---------|-----|--------|---------|
| PostgreSQL | 2 cores | 2GB RAM | 20GB+ SSD |
| Redis | 1 core | 1GB RAM | 5GB SSD |
| PgBouncer | 0.5 cores | 256MB RAM | - |
| Application | 2 cores | 1GB RAM | 5GB SSD |

## Migration Process

### Step 1: Environment Preparation

1. **Clone or navigate to the project directory:**
   ```bash
   cd /path/to/JunosCommander
   ```

2. **Create production environment file:**
   ```bash
   cp .env.example .env.production
   ```

3. **Configure production environment variables:**
   ```bash
   # Edit .env.production with your production settings
   nano .env.production
   ```

   Example production configuration:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=junoscommander
   DB_USER=junoscommander_app
   DB_PASSWORD=secure_production_password

   # Redis Configuration
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_PASSWORD=secure_redis_password

   # Security
   SESSION_KEY=generate_32_byte_key_here
   JWT_SECRET=generate_32_byte_secret_here

   # Active Directory/LDAP
   AD_SERVER=ldaps://your-ad-server.com:636
   AD_BASE_DN=dc=yourcompany,dc=com
   AD_SERVICE_USER=svc_junoscommander
   AD_SERVICE_PASSWORD=ad_service_password

   # Notifications (Optional)
   SLACK_WEBHOOK_URL=https://hooks.slack.com/...
   NOTIFICATION_EMAIL=admin@yourcompany.com
   ```

4. **Create secrets directory and files:**
   ```bash
   mkdir -p secrets
   echo "your_postgres_password" > secrets/postgres_password.txt
   echo "your_db_password" > secrets/db_password.txt
   echo "your_redis_password" > secrets/redis_password.txt
   # ... create other secret files as needed
   ```

### Step 2: Database Services Setup

1. **Start PostgreSQL and Redis services:**
   ```bash
   # Start core database services
   docker-compose -f docker-compose.prod.yml up -d postgres redis pgbouncer
   ```

2. **Wait for services to be ready:**
   ```bash
   # Check service health
   docker-compose -f docker-compose.prod.yml ps
   docker-compose -f docker-compose.prod.yml logs postgres
   ```

3. **Verify database initialization:**
   ```bash
   # Connect to PostgreSQL to verify setup
   docker exec -it junoscommander-postgres psql -U postgres -d junoscommander -c "\dt"
   ```

### Step 3: Data Migration

1. **Backup existing SQLite database:**
   ```bash
   cp data/junoscommander.db data/junoscommander.db.backup
   ```

2. **Run the migration script:**
   ```bash
   # Dry run first to validate connections
   ./scripts/migration/migrate.sh --dry-run

   # Run actual migration
   ./scripts/migration/migrate.sh --sqlite-path data/junoscommander.db
   ```

3. **Verify migration results:**
   ```bash
   # Check migration logs
   cat scripts/migration/migration.log

   # Verify data in PostgreSQL
   docker exec -it junoscommander-postgres psql -U junoscommander_app -d junoscommander -c "
   SELECT
     (SELECT count(*) FROM devices) as devices,
     (SELECT count(*) FROM users) as users,
     (SELECT count(*) FROM tasks) as tasks;
   "
   ```

### Step 4: Application Configuration Update

1. **Update application configuration to use PostgreSQL:**

   If using Go application, update database connection:
   ```go
   // Update database connection string
   dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
       os.Getenv("DB_HOST"),
       os.Getenv("DB_PORT"),
       os.Getenv("DB_USER"),
       os.Getenv("DB_PASSWORD"),
       os.Getenv("DB_NAME"))
   ```

2. **Update Redis configuration:**
   ```go
   // Redis connection for sessions
   redisClient := redis.NewClient(&redis.Options{
       Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
       Password: os.Getenv("REDIS_PASSWORD"),
       DB:       0, // Use DB 0 for sessions
   })
   ```

### Step 5: Start Production Services

1. **Start all production services:**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

2. **Verify service health:**
   ```bash
   # Check all services are running
   docker-compose -f docker-compose.prod.yml ps

   # Test application endpoint
   curl -f http://localhost:8080/health
   ```

3. **Run comprehensive health check:**
   ```bash
   cd scripts/monitoring
   python3 db_health_check.py --config health_check_config.json
   ```

### Step 6: Setup Automated Backups

1. **Test backup script:**
   ```bash
   ./scripts/backup/postgres_backup.sh --type schema
   ./scripts/backup/postgres_backup.sh --type full
   ```

2. **Setup cron jobs for automated backups:**
   ```bash
   # Add to crontab
   crontab -e
   ```

   Add these entries:
   ```cron
   # Daily full backup at 2 AM
   0 2 * * * /path/to/JunosCommander/scripts/backup/postgres_backup.sh --type full

   # Hourly incremental backups during business hours
   0 9-17 * * 1-5 /path/to/JunosCommander/scripts/backup/postgres_backup.sh --type incremental

   # Health checks every 5 minutes
   */5 * * * * /path/to/JunosCommander/scripts/monitoring/db_health_check.py --quiet
   ```

### Step 7: Performance Optimization

1. **Run VACUUM and ANALYZE on PostgreSQL:**
   ```sql
   -- Connect to database and run optimization
   VACUUM ANALYZE;

   -- Update table statistics
   ANALYZE;
   ```

2. **Warm up Redis cache:**
   ```bash
   # Pre-load frequently accessed data
   # This depends on your application's caching strategy
   ```

3. **Monitor initial performance:**
   ```bash
   # Watch database performance
   docker exec -it junoscommander-postgres psql -U junoscommander_app -d junoscommander -c "
   SELECT
     schemaname,
     tablename,
     n_tup_ins + n_tup_upd + n_tup_del as modifications,
     n_dead_tup as dead_tuples
   FROM pg_stat_user_tables
   ORDER BY modifications DESC;
   "
   ```

## Configuration Files Reference

### PostgreSQL Configuration
- **Location**: `postgres/postgresql.conf`
- **Features**: Optimized for read-heavy workloads, replication-ready
- **Key settings**: Connection pooling, memory optimization, WAL archiving

### Redis Configuration
- **Location**: `redis/redis.conf`
- **Features**: Session persistence, memory management, security
- **Database allocation**:
  - DB 0: User sessions
  - DB 1: Device cache
  - DB 2: Command results cache
  - DB 3: Configuration cache
  - DB 4: Task status cache
  - DB 5: Authentication cache

### PgBouncer Configuration
- **Location**: `pgbouncer/pgbouncer.ini`
- **Pool mode**: Transaction (optimal for JunosCommander)
- **Connection limits**: 200 client connections, 25 database connections

## Troubleshooting

### Common Migration Issues

1. **Connection timeout during migration:**
   ```bash
   # Increase connection timeout in migration script
   export DB_CONNECT_TIMEOUT=30
   ```

2. **Out of memory during large migrations:**
   ```bash
   # Increase Docker memory limits
   docker-compose -f docker-compose.prod.yml down
   # Edit docker-compose.prod.yml to increase memory limits
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **PostgreSQL initialization fails:**
   ```bash
   # Check PostgreSQL logs
   docker-compose -f docker-compose.prod.yml logs postgres

   # Reset PostgreSQL data
   docker-compose -f docker-compose.prod.yml down
   docker volume rm junoscommander_postgres-data
   docker-compose -f docker-compose.prod.yml up -d postgres
   ```

4. **Redis connection issues:**
   ```bash
   # Test Redis connectivity
   docker exec -it junoscommander-redis redis-cli -a $(cat secrets/redis_password.txt) ping
   ```

### Performance Issues

1. **Slow query performance:**
   ```sql
   -- Check for missing indexes
   SELECT schemaname, tablename, attname, n_distinct, correlation
   FROM pg_stats
   WHERE schemaname = 'public'
   ORDER BY n_distinct DESC;

   -- Check slow queries
   SELECT query, mean_exec_time, calls
   FROM pg_stat_statements
   ORDER BY mean_exec_time DESC
   LIMIT 10;
   ```

2. **High memory usage:**
   ```bash
   # Check PostgreSQL memory usage
   docker exec -it junoscommander-postgres psql -U postgres -c "
   SELECT name, setting, unit FROM pg_settings
   WHERE name IN ('shared_buffers', 'effective_cache_size', 'work_mem');
   "
   ```

3. **Connection pool exhaustion:**
   ```bash
   # Check PgBouncer stats
   docker exec -it junoscommander-pgbouncer psql -h localhost -U pgbouncer_admin -d pgbouncer -c "SHOW STATS;"
   ```

### Recovery Procedures

1. **Restore from backup:**
   ```bash
   # Stop application
   docker-compose -f docker-compose.prod.yml stop junoscommander

   # Restore database
   gunzip -c backups/full/junoscommander_full_YYYYMMDD_HHMMSS.sql.gz | \
   docker exec -i junoscommander-postgres psql -U postgres -d junoscommander

   # Or restore from custom format
   docker exec -i junoscommander-postgres pg_restore -U postgres -d junoscommander \
   /path/to/backup.custom
   ```

2. **Rollback to SQLite:**
   ```bash
   # Stop production services
   docker-compose -f docker-compose.prod.yml down

   # Restore original configuration
   # Update application to use SQLite again
   # Start with original docker-compose.yml
   docker-compose up -d
   ```

## Monitoring and Maintenance

### Daily Tasks
- Review backup logs
- Check database health status
- Monitor disk space usage

### Weekly Tasks
- Run full database backup
- Analyze query performance
- Review security logs

### Monthly Tasks
- Update database statistics
- Review and tune performance
- Test disaster recovery procedures
- Update documentation

## Security Considerations

1. **Network Security:**
   - Use TLS for all database connections in production
   - Implement firewall rules to restrict database access
   - Use VPN or private networks for database connectivity

2. **Access Control:**
   - Regularly rotate database passwords
   - Review user permissions quarterly
   - Implement principle of least privilege

3. **Data Protection:**
   - Encrypt backups
   - Secure backup storage location
   - Implement data retention policies

4. **Monitoring:**
   - Enable audit logging
   - Monitor failed authentication attempts
   - Set up alerts for suspicious activity

## Support and Documentation

- **Database Configuration Files**: See `postgres/`, `redis/`, `pgbouncer/` directories
- **Migration Scripts**: See `scripts/migration/` directory
- **Backup Scripts**: See `scripts/backup/` directory
- **Monitoring Tools**: See `scripts/monitoring/` directory
- **Docker Configurations**: See `docker-compose.prod.yml`

For additional support:
1. Check application logs: `docker-compose -f docker-compose.prod.yml logs`
2. Review database logs: `docker exec -it junoscommander-postgres tail -f /var/log/postgresql/postgresql-*.log`
3. Run health checks: `python3 scripts/monitoring/db_health_check.py`

## Performance Benchmarks

Expected performance after migration:

| Metric | Target | Notes |
|--------|--------|-------|
| Device lookup | < 10ms | With proper indexing |
| Task execution | < 100ms | Per device command |
| Session access | < 5ms | Redis cached |
| Backup time | < 30min | For 10,000 devices |
| Connection pool | 95%+ efficiency | With PgBouncer |
| Cache hit ratio | > 95% | PostgreSQL buffer cache |
| Redis hit ratio | > 90% | Application cache |

## Next Steps

After successful migration:

1. **Optimize Performance**: Monitor and tune database parameters based on actual usage
2. **Setup Monitoring**: Implement comprehensive monitoring with Grafana/Prometheus
3. **Disaster Recovery**: Test and document disaster recovery procedures
4. **Security Hardening**: Implement additional security measures for production
5. **Scale Planning**: Plan for horizontal scaling as device count grows

Remember to update your operational procedures and documentation to reflect the new database architecture.