# JunosCommander System Architecture

## Overview
JunosCommander is a production-ready network automation platform designed for managing Juniper Networks devices at scale with enterprise-grade security and high concurrency.

## High-Level Architecture Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Web Browser]
        API[REST API Client]
    end

    subgraph "Application Layer"
        WebUI[Web UI<br/>HTMX + Tailwind]
        RestAPI[REST API<br/>Gin Framework]
        WebSocket[WebSocket<br/>Real-time Updates]
    end

    subgraph "Authentication & Security"
        Auth[Authentication Service<br/>AD/LDAP Integration]
        Session[Session Manager<br/>AES-256-GCM Encryption]
        RBAC[Role-Based Access Control]
    end

    subgraph "Core Services"
        DeviceManager[Device Manager<br/>Inventory & Metadata]
        TaskExecutor[Task Executor<br/>Command Orchestration]
        ConfigManager[Config Manager<br/>Two-phase Commit]
        SSHPool[SSH Connection Pool<br/>100+ Concurrent Connections]
    end

    subgraph "Data Layer"
        PostgreSQL[(PostgreSQL<br/>Production DB)]
        SQLite[(SQLite<br/>Development DB)]
        Redis[(Redis<br/>Session Store &<br/>Distributed Lock)]
    end

    subgraph "External Systems"
        AD[Active Directory/<br/>LDAP Server]
        TACACS[TACACS+<br/>Device Auth]
        NetworkDevices[Network Devices<br/>Juniper/Cisco/Arista]
    end

    subgraph "Observability"
        Prometheus[Prometheus<br/>Metrics]
        Logging[Structured Logging<br/>Zap Logger]
        Audit[Audit Trail<br/>Compliance]
    end

    Browser --> WebUI
    API --> RestAPI
    WebUI --> RestAPI
    WebUI -.->|Live Updates| WebSocket

    RestAPI --> Auth
    RestAPI --> DeviceManager
    RestAPI --> TaskExecutor
    RestAPI --> ConfigManager

    Auth --> AD
    Auth --> Session
    Session --> Redis

    DeviceManager --> PostgreSQL
    DeviceManager --> SQLite

    TaskExecutor --> SSHPool
    TaskExecutor --> Redis
    SSHPool --> TACACS
    SSHPool --> NetworkDevices

    ConfigManager --> PostgreSQL
    ConfigManager --> NetworkDevices

    TaskExecutor --> Audit
    RestAPI --> Logging
    RestAPI --> Prometheus
```

## Component Architecture

```mermaid
graph LR
    subgraph "cmd/server"
        Main[main.go<br/>Entry Point]
    end

    subgraph "internal/api"
        APIHandler[API Handler<br/>REST Endpoints]
    end

    subgraph "internal/web"
        WebHandler[Web Handler<br/>HTML Templates]
    end

    subgraph "internal/auth"
        AuthManager[Auth Manager]
        Middleware[Auth Middleware]
        SessionMgr[Session Manager]
    end

    subgraph "internal/device"
        DeviceMgr[Device Manager<br/>CRUD Operations]
    end

    subgraph "internal/task"
        TaskExec[Task Executor<br/>Worker Pool]
    end

    subgraph "internal/ssh"
        SSHClient[SSH Pool<br/>Connection Management]
    end

    subgraph "internal/database"
        Models[Data Models]
        DBConn[Database Connection]
    end

    subgraph "internal/config"
        Config[Configuration<br/>Management]
    end

    Main --> APIHandler
    Main --> WebHandler
    APIHandler --> AuthManager
    WebHandler --> AuthManager
    AuthManager --> Middleware
    AuthManager --> SessionMgr
    APIHandler --> DeviceMgr
    APIHandler --> TaskExec
    TaskExec --> SSHClient
    DeviceMgr --> DBConn
    DBConn --> Models
    Main --> Config
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant WebUI
    participant API
    participant Auth
    participant TaskExecutor
    participant SSHPool
    participant Device
    participant DB
    participant Audit

    User->>WebUI: Login Request
    WebUI->>API: POST /auth/login
    API->>Auth: Validate Credentials
    Auth->>Auth: AD/LDAP Authentication
    Auth->>API: Return JWT Token
    API->>DB: Store Session
    API->>WebUI: Success + Token

    User->>WebUI: Execute Command
    WebUI->>API: POST /tasks/execute
    API->>Auth: Validate Token
    API->>TaskExecutor: Create Task
    TaskExecutor->>DB: Store Task
    TaskExecutor->>SSHPool: Get Connection
    SSHPool->>Device: SSH Connect (TACACS+)
    Device->>SSHPool: Connection Established
    SSHPool->>Device: Execute Command
    Device->>SSHPool: Command Output
    SSHPool->>TaskExecutor: Return Results
    TaskExecutor->>DB: Update Task Status
    TaskExecutor->>Audit: Log Activity
    TaskExecutor->>API: Task Complete
    API->>WebUI: Return Results
    WebUI->>User: Display Output
```

## Security Architecture

```mermaid
graph TD
    subgraph "Security Layers"
        TLS[TLS/HTTPS<br/>Transport Security]
        Auth[Authentication<br/>AD/LDAP]
        Session[Session Security<br/>AES-256-GCM]
        RBAC[Authorization<br/>Role-Based Access]
        Audit[Audit Logging<br/>Complete Trail]
    end

    subgraph "Credential Management"
        NoStore[Zero Credential Storage<br/>Memory-Only]
        Encrypt[In-Memory Encryption]
        TACACS[TACACS+ Integration<br/>Device Auth]
    end

    subgraph "Security Controls"
        RateLimit[Rate Limiting<br/>Brute Force Protection]
        Input[Input Validation<br/>SQL Injection Prevention]
        Timeout[Session Timeout<br/>Idle Detection]
        Logs[Security Logging<br/>Threat Detection]
    end

    TLS --> Auth
    Auth --> Session
    Session --> RBAC
    RBAC --> Audit

    NoStore --> Encrypt
    Encrypt --> TACACS

    RateLimit --> Input
    Input --> Timeout
    Timeout --> Logs
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Development Environment"
        DevDocker[Docker Compose<br/>All-in-One]
        DevDB[SQLite<br/>Local DB]
        DevRedis[Redis<br/>Local Cache]
    end

    subgraph "Production Environment"
        subgraph "Container Orchestration"
            K8s[Kubernetes Cluster]
            Pods[Application Pods<br/>Horizontal Scaling]
            Service[Load Balancer<br/>Service]
        end

        subgraph "Data Tier"
            ProdDB[PostgreSQL<br/>HA Cluster]
            ProdRedis[Redis Sentinel<br/>HA Cache]
        end

        subgraph "Monitoring"
            Prom[Prometheus<br/>Metrics]
            Grafana[Grafana<br/>Dashboards]
            ELK[ELK Stack<br/>Log Aggregation]
        end
    end

    subgraph "Infrastructure"
        LB[Load Balancer<br/>SSL Termination]
        Firewall[Firewall<br/>Network Security]
        Backup[Backup System<br/>Data Protection]
    end

    LB --> Service
    Service --> Pods
    Pods --> ProdDB
    Pods --> ProdRedis
    Pods --> Prom
    Pods --> ELK
```

## Task Execution Flow

```mermaid
graph LR
    subgraph "Task Queue System"
        Queue[Task Queue]
        Workers[Worker Pool<br/>Configurable Size]
        Scheduler[Task Scheduler<br/>Priority & Retry]
    end

    subgraph "Execution Pipeline"
        Validate[Validate Task]
        Acquire[Acquire SSH Connection]
        Execute[Execute Commands]
        Process[Process Output]
        Store[Store Results]
    end

    subgraph "Error Handling"
        Retry[Retry Logic<br/>Exponential Backoff]
        Fallback[Fallback Strategy]
        Alert[Error Alerting]
    end

    Queue --> Workers
    Workers --> Scheduler
    Scheduler --> Validate
    Validate --> Acquire
    Acquire --> Execute
    Execute --> Process
    Process --> Store

    Execute -.->|Error| Retry
    Retry -.->|Max Retries| Fallback
    Fallback -.-> Alert
```

## Database Schema Overview

```mermaid
erDiagram
    USERS ||--o{ SESSIONS : has
    USERS ||--o{ AUDIT_LOGS : creates
    USERS {
        int id PK
        string username
        string email
        string role
        datetime created_at
        datetime last_login
    }

    DEVICES ||--o{ TASKS : target
    DEVICES ||--o{ DEVICE_TAGS : has
    DEVICES {
        int id PK
        string hostname
        string ip_address
        string site
        string device_type
        string status
        json metadata
        datetime created_at
    }

    TASKS ||--o{ TASK_RESULTS : produces
    TASKS {
        int id PK
        string task_type
        string status
        json parameters
        int device_id FK
        int user_id FK
        datetime created_at
        datetime completed_at
    }

    SESSIONS {
        string id PK
        int user_id FK
        string token
        datetime expires_at
    }

    AUDIT_LOGS {
        int id PK
        int user_id FK
        string action
        json details
        string ip_address
        datetime timestamp
    }

    TASK_RESULTS {
        int id PK
        int task_id FK
        text output
        string status
        json metadata
    }

    DEVICE_TAGS {
        int id PK
        int device_id FK
        string tag_name
        string tag_value
    }
```

## Technology Stack Details

### Backend
- **Language**: Go 1.21+
- **Web Framework**: Gin (High-performance HTTP router)
- **Database**: PostgreSQL (Production), SQLite (Development)
- **Cache**: Redis (Session store, distributed locking)
- **SSH**: golang.org/x/crypto/ssh
- **Authentication**: go-ldap/ldap/v3

### Frontend
- **UI Framework**: HTMX (Dynamic updates without JavaScript frameworks)
- **CSS**: Tailwind CSS (Utility-first styling)
- **Templates**: Go HTML templates
- **Real-time**: WebSockets for live updates

### Infrastructure
- **Containerization**: Docker (Multi-stage builds)
- **Orchestration**: Kubernetes-ready
- **Monitoring**: Prometheus + Grafana
- **Logging**: Structured logging with Zap
- **CI/CD**: GitHub Actions compatible

## Performance Characteristics

| Metric | Specification |
|--------|--------------|
| Concurrent SSH Connections | 100+ |
| Device Inventory Size | 1000+ devices |
| Task Execution Throughput | 50+ tasks/second |
| API Response Time | < 100ms (p95) |
| WebSocket Latency | < 50ms |
| Session Encryption | AES-256-GCM |
| Database Connection Pool | Configurable (default: 25) |
| Worker Pool Size | Configurable (default: 10) |

## Security Features

### Authentication & Authorization
- Active Directory/LDAP integration
- JWT-based session management
- Role-based access control (RBAC)
- Multi-factor authentication ready

### Data Protection
- Zero credential storage (memory-only)
- AES-256-GCM encryption for sessions
- TLS/HTTPS enforcement
- Input validation and sanitization

### Audit & Compliance
- Complete audit trail of all actions
- Structured security logging
- Compliance-ready reporting
- Data retention policies

### Network Security
- TACACS+ for device authentication
- Rate limiting and DDoS protection
- IP allowlisting capability
- Secure WebSocket connections

## Scalability & High Availability

### Horizontal Scaling
- Stateless application design
- Shared session store (Redis)
- Load balancer ready
- Database connection pooling

### High Availability
- Multi-instance deployment support
- Redis Sentinel for cache HA
- PostgreSQL replication support
- Health check endpoints

### Performance Optimization
- Connection pooling (SSH & Database)
- Concurrent task execution
- Efficient device filtering
- Caching strategies

## Monitoring & Observability

### Metrics (Prometheus)
- `ssh_connections_active`: Current SSH connections
- `task_execution_duration`: Task completion times
- `api_request_duration`: API response times
- `auth_attempts_total`: Authentication attempts
- `device_operations_total`: Device operation counts

### Health Endpoints
- `/health`: Application liveness
- `/ready`: Readiness probe
- `/metrics`: Prometheus metrics

### Logging
- Structured JSON logging
- Log levels: DEBUG, INFO, WARN, ERROR
- Correlation IDs for request tracing
- Audit log separation

## Integration Points

### External Systems
1. **Active Directory/LDAP**
   - User authentication
   - Group membership validation

2. **TACACS+ Server**
   - Device authentication
   - Command authorization

3. **Network Devices**
   - Juniper (Primary)
   - Cisco (Supported)
   - Arista (Supported)

### API Integration
- RESTful API design
- JWT authentication
- JSON request/response
- WebSocket for real-time updates

## Disaster Recovery

### Backup Strategy
- Database backups (automated)
- Configuration backups
- Audit log archival
- Recovery time objective (RTO): < 1 hour

### Failover Capabilities
- Automatic session migration
- Graceful shutdown handling
- Task queue persistence
- Connection pool recovery

## Future Enhancements (Roadmap)

1. **Phase 1**: Core Functionality ✅
   - Basic device management
   - Command execution
   - Authentication integration

2. **Phase 2**: Advanced Features
   - Configuration management
   - Scheduled tasks
   - Bulk operations

3. **Phase 3**: Enterprise Features
   - Multi-tenancy support
   - Advanced RBAC
   - Compliance reporting
   - API rate limiting

4. **Phase 4**: Automation
   - Workflow engine
   - Event-driven automation
   - Integration with CI/CD
   - Network validation framework