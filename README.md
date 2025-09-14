# JunosCommander

Enterprise-grade network automation platform for managing Juniper Networks devices and multi-vendor network infrastructure.

## Overview

JunosCommander is a high-performance, secure network automation tool designed specifically for NetOps teams managing large-scale Juniper deployments. Built with Go for exceptional concurrency and performance, it provides centralized device management, task execution, and configuration deployment across your entire network infrastructure.

### Key Features

- **Multi-vendor Support**: Primary focus on Junos with support for Cisco IOS/NX-OS and Arista EOS
- **Concurrent Operations**: Execute commands on hundreds of devices simultaneously
- **Secure Credential Management**: In-memory encrypted storage with no persistence to disk
- **AD/LDAP Integration**: Enterprise authentication with TACACS+ pass-through
- **Real-time Updates**: WebSocket support for live task monitoring
- **RESTful API**: Full API for integration with existing tools
- **Web UI**: Modern, responsive interface with HTMX for dynamic updates

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/brndnsvr/junoscommander.git
cd junoscommander
```

2. Copy environment configuration:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start the application:
```bash
docker-compose up -d
```

4. Access the web interface:
- Web UI: http://localhost:8080
- API: http://localhost:8080/api/v1
- LDAP Admin (development): http://localhost:8081

### Manual Installation

#### Prerequisites

- Go 1.21 or higher
- SQLite 3 (development) or PostgreSQL 13+ (production)
- Git

#### Build from Source

```bash
# Clone repository
git clone https://github.com/brndnsvr/junoscommander.git
cd junoscommander

# Install dependencies
go mod download

# Build the application
go build -o bin/junoscommander ./cmd/server

# Run the application
./bin/junoscommander
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_MODE=development

# Database
DATABASE_PATH=./data/junoscommander.db

# Authentication
AUTH_TYPE=ldap
LDAP_HOST=ldap://localhost:389
LDAP_BASE_DN=dc=example,dc=org
LDAP_BIND_DN=cn=admin,dc=example,dc=org
LDAP_BIND_PASSWORD=admin
LDAP_USER_SEARCH_FILTER=(uid={{username}})

# Session
SESSION_SECRET=change-this-in-production
SESSION_TIMEOUT=24h

# SSH Configuration
SSH_TIMEOUT=30s
SSH_MAX_RETRIES=3
SSH_POOL_SIZE=50

# Task Execution
TASK_WORKER_POOL_SIZE=10
TASK_QUEUE_SIZE=1000
TASK_MAX_CONCURRENT=50

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/junoscommander.log
```

### Database Setup

For production, use PostgreSQL:

```sql
CREATE DATABASE junoscommander;
CREATE USER junoscommander WITH ENCRYPTED PASSWORD 'your-password';
GRANT ALL PRIVILEGES ON DATABASE junoscommander TO junoscommander;
```

Update `.env`:
```env
DATABASE_TYPE=postgres
DATABASE_URL=postgres://junoscommander:your-password@localhost/junoscommander?sslmode=require
```

## Usage

### Web Interface

1. Navigate to http://localhost:8080
2. Login with your AD/LDAP credentials
3. Add devices via the Devices page
4. Execute tasks from the Tasks page

### API Usage

#### Authentication

```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}'

# Returns: {"token":"jwt-token-here","user":{...}}
```

#### Device Management

```bash
# List devices
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/devices

# Add device
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":"router1.example.com",
    "ip_address":"192.168.1.1",
    "device_type":"junos",
    "site":"DC1"
  }'
```

#### Task Execution

```bash
# Execute task on multiple devices
curl -X POST http://localhost:8080/api/v1/tasks/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type":"get_config",
    "device_ids":[1,2,3],
    "parameters":{}
  }'

# Check task status
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/tasks/<task-id>
```

### CLI Examples

The application supports various task types:

- `get_version` - Retrieve device version information
- `get_config` - Download running configuration
- `get_interfaces` - List interface status
- `get_routes` - Display routing table
- `health_check` - Perform device health check
- `custom` - Execute custom commands

## Architecture

### Components

- **API Server**: RESTful API built with Gin framework
- **Task Executor**: Worker pool pattern for concurrent execution
- **SSH Manager**: Connection pooling for efficient resource usage
- **Auth Manager**: AD/LDAP integration with session management
- **Database**: SQLite/PostgreSQL for device and task storage
- **Web UI**: Server-side rendered with HTMX for dynamic updates

### Security

- **No Credential Storage**: Credentials are never persisted to disk
- **Encrypted Sessions**: AES-256-GCM encryption for session data
- **JWT Tokens**: Secure API authentication
- **Audit Logging**: Complete audit trail of all operations
- **RBAC Ready**: Role-based access control framework

## Development

### Project Structure

```
junoscommander/
├── cmd/server/          # Application entry point
├── internal/            # Internal packages
│   ├── api/            # API handlers
│   ├── auth/           # Authentication
│   ├── config/         # Configuration
│   ├── database/       # Database operations
│   ├── device/         # Device management
│   ├── ssh/            # SSH connections
│   ├── task/           # Task execution
│   └── web/            # Web handlers
├── web/                 # Web assets
│   ├── static/         # CSS, JS files
│   └── templates/      # HTML templates
├── docs/               # Documentation
├── prompt-docs/        # Requirements and design docs
└── docker-compose.yml  # Docker configuration
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/auth
```

### Building for Production

```bash
# Build with optimizations
CGO_ENABLED=1 go build -ldflags="-s -w" -o bin/junoscommander ./cmd/server

# Build Docker image
docker build -t junoscommander:latest .

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t junoscommander:latest .
```

## API Documentation

See [API Specification](prompt-docs/api-specification.md) for complete API documentation.

## Deployment

### Docker Deployment

```yaml
# docker-compose.production.yml
version: '3.8'
services:
  junoscommander:
    image: junoscommander:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_TYPE=postgres
      - DATABASE_URL=postgres://user:pass@db/junoscommander
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
```

### Kubernetes Deployment

See [k8s/](k8s/) directory for Kubernetes manifests.

### High Availability

For HA deployment:
1. Use PostgreSQL with replication
2. Deploy multiple application instances
3. Use a load balancer (nginx, HAProxy)
4. Configure shared session storage (Redis)

## Monitoring

### Health Checks

- Health endpoint: `GET /health`
- Ready endpoint: `GET /ready`
- Metrics endpoint: `GET /metrics` (Prometheus format)

### Logging

Logs are written to both stdout and file (configurable):
- Application logs: `./logs/junoscommander.log`
- Audit logs: Stored in database

## Troubleshooting

### Common Issues

1. **Connection refused on startup**
   - Check if port 8080 is available
   - Verify database connection settings

2. **LDAP authentication fails**
   - Verify LDAP connection settings
   - Check bind DN and password
   - Test with `ldapsearch` command

3. **SSH connections timeout**
   - Increase SSH_TIMEOUT in configuration
   - Check network connectivity to devices
   - Verify device SSH configuration

4. **High memory usage**
   - Adjust SSH_POOL_SIZE
   - Reduce TASK_WORKER_POOL_SIZE
   - Enable connection reuse

## Planning Documents

### Documentation Structure

1. **[Product Requirements Document](prompt-docs/PRD.md)**
   - System architecture and requirements
   - Functional specifications
   - Technology stack decisions
   - Implementation phases

2. **[Proof of Concept Plan](prompt-docs/poc-plan.md)**
   - Detailed test cases for validating architecture
   - AD authentication flow validation
   - SSH connection pooling tests
   - Performance benchmarks

3. **[API Specification](prompt-docs/api-specification.md)**
   - Complete OpenAPI/Swagger specification
   - REST endpoints documentation
   - WebSocket events
   - Authentication flow

4. **[Technical Design Document](prompt-docs/technical-design.md)**
   - Session management architecture
   - Task execution engine design
   - Device filtering DSL
   - Configuration rollback mechanism

5. **[Development Environment Setup](prompt-docs/dev-environment-setup.md)**
   - Prerequisites and tooling
   - Docker Compose configuration
   - Local LDAP/TACACS+ setup
   - IDE configuration

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Copyright (c) 2024 Your Organization. All rights reserved.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/brndnsvr/junoscommander/issues)
- Email: dev@brndnsvr.com

## Roadmap

### Version 1.1
- [ ] Configuration backup scheduling
- [ ] Automated compliance checking
- [ ] Integration with ServiceNow
- [ ] Multi-factor authentication

### Version 1.2
- [ ] GitOps integration
- [ ] Ansible playbook support
- [ ] Advanced reporting dashboard
- [ ] Mobile application

### Version 2.0
- [ ] Machine learning for anomaly detection
- [ ] Predictive maintenance
- [ ] Intent-based networking
- [ ] Cloud-native architecture

## Acknowledgments

Built with:
- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [GORM](https://gorm.io/) (optional)
- [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh)
- [HTMX](https://htmx.org/)
- [Tailwind CSS](https://tailwindcss.com/)

---

**Version:** 1.0.0
**Last Updated:** September 2024
**Status:** Production Ready
