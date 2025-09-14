# Development Environment Setup Guide

## Prerequisites

### Required Software
- **Go**: 1.21 or higher
- **Python**: 3.11 or higher (for database tools)
- **Docker**: 20.10 or higher
- **Docker Compose**: 2.0 or higher
- **Git**: 2.30 or higher
- **Make**: GNU Make 3.81 or higher

### Recommended IDE Setup
- **VS Code** with extensions:
  - Go (official)
  - Python
  - Docker
  - YAML
  - GitLens
- **GoLand** (JetBrains)
- **Cursor** with Go support

## 1. Initial Setup

### 1.1 Clone Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/network-automation-platform.git
cd network-automation-platform

# Create necessary directories
mkdir -p configs data logs scripts/venv web/static web/templates
```

### 1.2 Environment Variables

Create `.env` file from template:

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
# Active Directory
AD_SERVICE_USER=svc_netautomation
AD_SERVICE_PASSWORD=your_service_password
AD_SERVER_1=ad1.example.com
AD_SERVER_2=ad2.example.com
AD_BASE_DN=DC=example,DC=com

# Session Security
SESSION_ENCRYPTION_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)

# Database
DB_PATH=./data/network_automation.db
DB_BACKUP_PATH=./data/backups

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0
TLS_ENABLED=false  # Set to true for production

# Logging
LOG_LEVEL=debug
LOG_FILE=./logs/app.log
AUDIT_LOG_FILE=./logs/audit.log
```

### 1.3 Go Dependencies

```bash
# Initialize Go module (if not already done)
go mod init github.com/yourusername/network-automation-platform

# Download dependencies
go mod download

# Verify dependencies
go mod verify

# Tidy up
go mod tidy
```

### 1.4 Python Virtual Environment

```bash
# Create virtual environment for Python tools
cd scripts
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

Create `scripts/requirements.txt`:

```txt
click==8.1.7
pyyaml==6.0.1
requests==2.31.0
tabulate==0.9.0
colorama==0.4.6
python-dotenv==1.0.0
```

## 2. Local Development Stack

### 2.1 Docker Compose Setup

Create `docker-compose.dev.yml`:

```yaml
version: '3.8'

services:
  # OpenLDAP for AD simulation
  openldap:
    image: osixia/openldap:1.5.0
    container_name: dev-ldap
    environment:
      LDAP_ORGANISATION: "Example Corp"
      LDAP_DOMAIN: "example.com"
      LDAP_BASE_DN: "dc=example,dc=com"
      LDAP_ADMIN_PASSWORD: "admin"
      LDAP_CONFIG_PASSWORD: "config"
      LDAP_RFC2307BIS_SCHEMA: "false"
      LDAP_TLS: "false"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ./dev/ldap/data:/var/lib/ldap
      - ./dev/ldap/config:/etc/ldap/slapd.d
      - ./dev/ldap/ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom
    networks:
      - dev-net

  # phpLDAPadmin for LDAP management
  phpldapadmin:
    image: osixia/phpldapadmin:latest
    container_name: dev-ldap-admin
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: "openldap"
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "8081:80"
    depends_on:
      - openldap
    networks:
      - dev-net

  # Mock TACACS+ server
  tacacs:
    build:
      context: ./dev/tacacs
      dockerfile: Dockerfile
    container_name: dev-tacacs
    ports:
      - "49:49"
    volumes:
      - ./dev/tacacs/config:/etc/tacacs
    networks:
      - dev-net

  # Redis for session storage (optional)
  redis:
    image: redis:7-alpine
    container_name: dev-redis
    ports:
      - "6379:6379"
    networks:
      - dev-net

  # Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: dev-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./dev/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - dev-net

  # Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: dev-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_SECURITY_ADMIN_USER=admin
    volumes:
      - ./dev/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./dev/grafana/datasources:/etc/grafana/provisioning/datasources
    networks:
      - dev-net

networks:
  dev-net:
    driver: bridge
```

### 2.2 TACACS+ Mock Server

Create `dev/tacacs/Dockerfile`:

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    tacacs+ \
    && rm -rf /var/lib/apt/lists/*

COPY config/tac_plus.conf /etc/tacacs+/tac_plus.conf

EXPOSE 49

CMD ["/usr/sbin/tac_plus", "-C", "/etc/tacacs+/tac_plus.conf", "-d", "16", "-f"]
```

Create `dev/tacacs/config/tac_plus.conf`:

```conf
# Mock TACACS+ configuration
key = "testing123"

# Define users that match LDAP
user = testuser {
    pap = cleartext "testpass"
    member = netadmins
}

user = operator {
    pap = cleartext "operpass"
    member = netoperators
}

# Groups
group = netadmins {
    default service = permit
    service = exec {
        priv-lvl = 15
    }
}

group = netoperators {
    default service = permit
    service = exec {
        priv-lvl = 1
    }
}

# Accounting
accounting file = /var/log/tac_plus.acct
```

### 2.3 Network Device Simulators

Create `dev/device-sim/docker-compose.yml`:

```yaml
version: '3.8'

services:
  # Containerlab for network simulation
  clab:
    image: ghcr.io/srl-labs/containerlab:latest
    container_name: dev-clab
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./topology.yml:/topology.yml
    command: deploy -t /topology.yml

  # Alternative: GNS3 server
  gns3:
    image: gns3/gns3-server:latest
    container_name: dev-gns3
    ports:
      - "3080:3080"
    volumes:
      - ./gns3/projects:/data/projects
      - ./gns3/images:/data/images
```

Create `dev/device-sim/topology.yml` for Containerlab:

```yaml
name: net-automation-lab

topology:
  nodes:
    router1:
      kind: linux
      image: nicolaka/netshoot:latest
      cmd: /bin/bash
    
    switch1:
      kind: linux  
      image: nicolaka/netshoot:latest
      cmd: /bin/bash

  links:
    - endpoints: ["router1:eth1", "switch1:eth1"]
```

## 3. Makefile for Development

Create `Makefile`:

```makefile
.PHONY: help dev test build clean

# Variables
BINARY_NAME=netautomation
GO_FILES=$(shell find . -name '*.go' -type f)
DOCKER_IMAGE=network-automation:dev

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m # No Color

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  ${GREEN}%-15s${NC} %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

dev: ## Start development environment
	@echo "${YELLOW}Starting development environment...${NC}"
	docker-compose -f docker-compose.dev.yml up -d
	@echo "${GREEN}Development environment started!${NC}"
	@echo "Services available:"
	@echo "  - LDAP Admin: http://localhost:8081"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Grafana: http://localhost:3000 (admin/admin)"

dev-stop: ## Stop development environment
	@echo "${YELLOW}Stopping development environment...${NC}"
	docker-compose -f docker-compose.dev.yml down
	@echo "${GREEN}Development environment stopped!${NC}"

dev-clean: ## Clean development environment
	@echo "${YELLOW}Cleaning development environment...${NC}"
	docker-compose -f docker-compose.dev.yml down -v
	rm -rf dev/ldap/data dev/ldap/config
	@echo "${GREEN}Development environment cleaned!${NC}"

build: ## Build the Go application
	@echo "${YELLOW}Building application...${NC}"
	go build -o bin/$(BINARY_NAME) ./cmd/server
	@echo "${GREEN}Build complete: bin/$(BINARY_NAME)${NC}"

run: build ## Build and run the application
	@echo "${YELLOW}Running application...${NC}"
	./bin/$(BINARY_NAME)

test: ## Run tests
	@echo "${YELLOW}Running tests...${NC}"
	go test -v -cover ./...
	@echo "${GREEN}Tests complete!${NC}"

test-integration: ## Run integration tests
	@echo "${YELLOW}Running integration tests...${NC}"
	go test -v -tags=integration ./test/integration/...
	@echo "${GREEN}Integration tests complete!${NC}"

lint: ## Run linter
	@echo "${YELLOW}Running linter...${NC}"
	golangci-lint run
	@echo "${GREEN}Linting complete!${NC}"

fmt: ## Format code
	@echo "${YELLOW}Formatting code...${NC}"
	go fmt ./...
	goimports -w $(GO_FILES)
	@echo "${GREEN}Formatting complete!${NC}"

db-init: ## Initialize database
	@echo "${YELLOW}Initializing database...${NC}"
	cd scripts && python db_manager.py init --db ../data/network_automation.db
	@echo "${GREEN}Database initialized!${NC}"

db-seed: db-init ## Seed database with test data
	@echo "${YELLOW}Seeding database...${NC}"
	cd scripts && python db_manager.py import ../sample_devices.csv --db ../data/network_automation.db
	@echo "${GREEN}Database seeded!${NC}"

docker-build: ## Build Docker image
	@echo "${YELLOW}Building Docker image...${NC}"
	docker build -t $(DOCKER_IMAGE) .
	@echo "${GREEN}Docker image built: $(DOCKER_IMAGE)${NC}"

docker-run: docker-build ## Run in Docker
	@echo "${YELLOW}Running in Docker...${NC}"
	docker run --rm -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

clean: ## Clean build artifacts
	@echo "${YELLOW}Cleaning...${NC}"
	rm -rf bin/
	rm -rf data/*.db
	rm -rf logs/*.log
	go clean
	@echo "${GREEN}Clean complete!${NC}"

install-tools: ## Install development tools
	@echo "${YELLOW}Installing development tools...${NC}"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	@echo "${GREEN}Tools installed!${NC}"

generate: ## Generate code (mocks, swagger, etc.)
	@echo "${YELLOW}Generating code...${NC}"
	go generate ./...
	swag init -g ./cmd/server/main.go
	@echo "${GREEN}Code generation complete!${NC}"

.DEFAULT_GOAL := help
```

## 4. LDAP Test Data

Create `dev/ldap/ldif/01-users.ldif`:

```ldif
# Organizational Units
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

# Groups
dn: cn=netadmins,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: netadmins
member: uid=admin,ou=users,dc=example,dc=com
member: uid=john.doe,ou=users,dc=example,dc=com

dn: cn=netoperators,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: netoperators
member: uid=operator,ou=users,dc=example,dc=com
member: uid=jane.smith,ou=users,dc=example,dc=com

# Users
dn: uid=admin,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: admin
cn: Admin User
sn: User
mail: admin@example.com
userPassword: {SSHA}YourHashHere

dn: uid=john.doe,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: john.doe
cn: John Doe
sn: Doe
mail: john.doe@example.com
userPassword: {SSHA}YourHashHere

dn: uid=jane.smith,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: jane.smith
cn: Jane Smith
sn: Smith
mail: jane.smith@example.com
userPassword: {SSHA}YourHashHere

dn: uid=operator,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: operator
cn: Operator User
sn: User
mail: operator@example.com
userPassword: {SSHA}YourHashHere
```

## 5. VS Code Configuration

### 5.1 `.vscode/launch.json`

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Server",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/cmd/server",
            "envFile": "${workspaceFolder}/.env",
            "args": []
        },
        {
            "name": "Launch CLI",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}/cmd/cli",
            "envFile": "${workspaceFolder}/.env",
            "args": ["devices", "list"]
        },
        {
            "name": "Debug Test",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}",
            "args": ["-test.v"]
        }
    ]
}
```

### 5.2 `.vscode/settings.json`

```json
{
    "go.lintTool": "golangci-lint",
    "go.lintFlags": [
        "--fast"
    ],
    "go.formatTool": "goimports",
    "go.testFlags": ["-v"],
    "go.testTimeout": "30s",
    "editor.formatOnSave": true,
    "[go]": {
        "editor.codeActionsOnSave": {
            "source.organizeImports": true
        }
    },
    "files.exclude": {
        "**/.git": true,
        "**/.DS_Store": true,
        "**/bin": true,
        "**/vendor": true
    }
}
```

### 5.3 `.vscode/tasks.json`

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build",
            "type": "shell",
            "command": "make build",
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": ["$go"]
        },
        {
            "label": "Test",
            "type": "shell",
            "command": "make test",
            "group": {
                "kind": "test",
                "isDefault": true
            },
            "problemMatcher": ["$go"]
        },
        {
            "label": "Start Dev Environment",
            "type": "shell",
            "command": "make dev",
            "problemMatcher": []
        }
    ]
}
```

## 6. Git Configuration

### 6.1 `.gitignore`

```gitignore
# Binaries
*.exe
*.exe~
*.dll
*.so
*.dylib
bin/

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool
*.out

# Dependency directories
vendor/

# Go workspace file
go.work

# Environment variables
.env
.env.local

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Application
data/*.db
data/backups/
logs/
*.log

# Python
scripts/venv/
scripts/__pycache__/
*.pyc

# Docker
dev/ldap/data/
dev/ldap/config/
```

### 6.2 Pre-commit Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/dnephin/pre-commit-golang
    rev: v0.5.1
    hooks:
      - id: go-fmt
      - id: go-vet
      - id: go-imports
      - id: go-cyclo
        args: [-over=15]
      - id: golangci-lint
```

Install pre-commit:

```bash
pip install pre-commit
pre-commit install
```

## 7. Quick Start Commands

```bash
# 1. Clone and setup
git clone <repo-url>
cd network-automation-platform
cp .env.example .env

# 2. Install dependencies
go mod download
make install-tools

# 3. Start development environment
make dev

# 4. Initialize and seed database
make db-seed

# 5. Run the application
make run

# 6. Run tests
make test

# 7. Access the application
open http://localhost:8080
```

## 8. Troubleshooting

### Common Issues

#### LDAP Connection Failed
```bash
# Check LDAP is running
docker ps | grep dev-ldap

# Test LDAP connection
ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com"
```

#### Database Locked
```bash
# Remove lock file
rm data/network_automation.db-journal

# Or reinitialize
make db-init
```

#### Port Already in Use
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>
```

#### Go Module Issues
```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download
```

## 9. Development Workflow

### 9.1 Feature Development

1. Create feature branch
```bash
git checkout -b feature/your-feature
```

2. Start dev environment
```bash
make dev
```

3. Make changes and test
```bash
make test
```

4. Format and lint
```bash
make fmt
make lint
```

5. Commit with conventional commits
```bash
git commit -m "feat: add new device filter"
```

### 9.2 Debugging

1. Use VS Code debugger with provided launch configurations
2. Add breakpoints in code
3. Launch "Debug Server" configuration
4. Trigger the code path you want to debug

### 9.3 Testing Against Real Devices

1. Set up GNS3 or EVE-NG with real device images
2. Configure devices with TACACS+ pointing to dev environment
3. Update `.env` with real device IPs
4. Run integration tests

```bash
make test-integration
```

## 10. Performance Profiling

### CPU Profiling
```go
import _ "net/http/pprof"

// In main.go
go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()
```

Access profiles:
```bash
go tool pprof http://localhost:6060/debug/pprof/profile
go tool pprof http://localhost:6060/debug/pprof/heap
```

### Benchmarking
```bash
go test -bench=. -benchmem ./...
```

## 11. Next Steps

1. Review the PRD and Technical Design documents
2. Set up your development environment
3. Run the PoC tests
4. Start implementing Phase 1 (Core Infrastructure)
5. Join the team chat/Slack for collaboration

## Support

For issues or questions:
- Check the troubleshooting section
- Review logs in `logs/` directory
- Contact the team lead
- Create an issue in the repository
