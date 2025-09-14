# JunosCommander Multi-Container Architecture Upgrade

## Overview

This document describes the key changes made to upgrade JunosCommander from a single-container SQLite-based application to a multi-container architecture with PostgreSQL, Redis, and enhanced observability.

## Architecture Changes

### Database Layer
- **Added PostgreSQL support** alongside SQLite for horizontal scaling
- **Configurable database backend** via `DB_TYPE` environment variable
- **Enhanced connection pooling** with customizable settings
- **PostgreSQL-specific features**: JSONB columns, array types, advanced indexing
- **Distributed locking** using database or Redis for multi-instance coordination

### Session Management
- **Redis-based session storage** replaces in-memory sessions
- **Distributed session sharing** across multiple application instances
- **Session persistence** survives application restarts
- **Configurable TTL** and automatic cleanup

### Observability & Monitoring
- **Comprehensive Prometheus metrics** for all application components
- **Structured JSON logging** with multiple specialized loggers
- **Enhanced health checks** with dependency validation
- **Performance monitoring** with slow query detection

### Resilience & Scalability
- **Graceful shutdown** with connection draining
- **Distributed locking** for coordination between instances
- **Circuit breakers** and retry logic for external dependencies
- **Zero-downtime deployments** support

## New Components

### 1. PostgreSQL Database (`internal/database/postgres.go`)
```go
// Key features:
- Connection pooling with configurable parameters
- Advanced PostgreSQL data types (JSONB, arrays, INET)
- Distributed locking using database locks
- Health checks with connection validation
- Migration system with PostgreSQL-specific schema
```

### 2. Redis Cache & Sessions (`internal/cache/redis.go`)
```go
// Key features:
- Redis client with connection pooling
- Session management with automatic expiration
- General-purpose caching with TTL support
- Health monitoring and statistics
- Distributed locking support
```

### 3. Prometheus Metrics (`internal/metrics/prometheus.go`)
```go
// Metrics collected:
- HTTP request metrics (latency, status codes, throughput)
- Database connection pool usage
- SSH connection statistics
- Task execution metrics
- Redis operation performance
- System resource usage
```

### 4. Health Checks (`internal/health/checker.go`)
```go
// Health checkers:
- Database connectivity and query performance
- Redis connectivity and response times
- Disk space availability
- Component-specific health validation
- Configurable thresholds and timeouts
```

### 5. Graceful Shutdown (`internal/shutdown/graceful.go`)
```go
// Shutdown features:
- Signal handling for SIGTERM/SIGINT
- Ordered component shutdown
- Connection draining for zero-downtime
- Timeout-based forced shutdown
- Resource cleanup management
```

### 6. Distributed Locking (`internal/lock/distributed.go`)
```go
// Locking providers:
- Database-based locks (PostgreSQL)
- Redis-based locks (with Lua scripts)
- Lock renewal and timeout handling
- Multi-instance coordination
```

### 7. Structured Logging (`internal/logger/logger.go`)
```go
// Specialized loggers:
- Security events (authentication, authorization)
- Audit trail (resource access, configuration changes)
- Performance monitoring (slow queries, resource usage)
- HTTP request logging with context
```

## Configuration Updates

### Environment Variables
```bash
# Database Configuration
DB_TYPE=postgres                    # sqlite or postgres
DB_HOST=localhost                   # PostgreSQL host
DB_PORT=5432                       # PostgreSQL port
DB_NAME=junoscommander             # Database name
DB_USER=postgres                   # Database user
DB_PASSWORD=your-password          # Database password
DB_SSL_MODE=require                # SSL mode
DB_MAX_CONNECTIONS=25              # Connection pool size
DB_CONN_MAX_LIFETIME=1h            # Connection lifetime

# Redis Configuration
REDIS_ADDRESS=localhost:6379       # Redis address
REDIS_PASSWORD=your-password       # Redis password
REDIS_DB=0                         # Redis database number
REDIS_POOL_SIZE=10                 # Connection pool size

# Logging Configuration
LOG_LEVEL=info                     # Log level
LOG_FORMAT=json                    # json or console
LOG_OUTPUT=stdout                  # Output destination

# Metrics Configuration
METRICS_ENABLED=true               # Enable Prometheus metrics
METRICS_PATH=/metrics              # Metrics endpoint path
```

## API Endpoints

### Health & Monitoring
- `GET /health` - Comprehensive health check with all components
- `GET /ready` - Kubernetes readiness probe
- `GET /live` - Kubernetes liveness probe
- `GET /metrics` - Prometheus metrics endpoint

### Debug (Development Only)
- `GET /debug/locks` - Show instance ID and locking status

## Deployment Changes

### Docker Compose
The application now requires:
- PostgreSQL container with persistent storage
- Redis container with persistence
- Application container with proper networking

### Environment Configuration
- **Development**: Uses SQLite + Redis for simplified setup
- **Production**: Uses PostgreSQL + Redis for scalability
- **High Availability**: Multiple app instances with load balancer

## Migration Guide

### From Single Container
1. **Add Redis container** to your deployment
2. **Add PostgreSQL container** (optional but recommended)
3. **Update environment variables** with new configuration
4. **Run database migrations** if switching to PostgreSQL
5. **Update monitoring** to scrape new metrics endpoint

### Database Migration
```bash
# Backup existing SQLite data
sqlite3 data/junoscommander.db .dump > backup.sql

# Import to PostgreSQL (manual process)
# Convert SQLite syntax to PostgreSQL syntax
# Run migrations with new schema
```

## Key Benefits

### Scalability
- **Horizontal scaling**: Multiple application instances
- **Database scaling**: PostgreSQL read replicas and clustering
- **Session sharing**: Redis-based sessions across instances

### Reliability
- **Graceful shutdown**: Zero-downtime deployments
- **Health monitoring**: Proactive issue detection
- **Distributed coordination**: Safe multi-instance operations

### Observability
- **Comprehensive metrics**: All application components monitored
- **Structured logging**: Machine-readable log format
- **Audit trail**: Complete security and change tracking

### Performance
- **Connection pooling**: Efficient resource utilization
- **Caching**: Redis-based performance optimization
- **Monitoring**: Real-time performance insights

## Backward Compatibility

- **SQLite mode**: Existing deployments continue to work
- **Configuration**: New variables have sensible defaults
- **API compatibility**: All existing endpoints unchanged
- **Data migration**: Manual process for PostgreSQL adoption

## Security Enhancements

- **Session security**: Redis-based session storage with encryption
- **Audit logging**: Comprehensive security event tracking
- **Credential handling**: Enhanced security for sensitive data
- **Network security**: Configurable SSL/TLS for all connections

## Performance Optimizations

- **Database**: Optimized queries and connection pooling
- **Caching**: Redis caching for frequently accessed data
- **Metrics**: Efficient metric collection with minimal overhead
- **Logging**: Asynchronous logging with batching

This upgrade transforms JunosCommander from a single-instance application into a production-ready, horizontally scalable system suitable for enterprise deployments.