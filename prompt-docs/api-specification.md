# Network Automation Platform - API Specification

## API Overview

This document defines the REST API for the Network Automation Platform. The API follows RESTful principles and uses JSON for request/response bodies.

## OpenAPI Specification

```yaml
openapi: 3.0.3
info:
  title: Network Automation Platform API
  description: API for managing network devices and executing automation tasks
  version: 1.0.0
  contact:
    name: Brandon Seaver
    email: seaverb@icloud.com

servers:
  - url: https://api.network-automation.local/v1
    description: Production server
  - url: http://localhost:8080/v1
    description: Development server

security:
  - bearerAuth: []

paths:
  /auth/login:
    post:
      tags:
        - Authentication
      summary: Authenticate user with AD credentials
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Successful authentication
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
        '401':
          description: Invalid credentials
        '423':
          description: Account locked
        '503':
          description: AD server unavailable

  /auth/logout:
    post:
      tags:
        - Authentication
      summary: Terminate user session
      responses:
        '204':
          description: Successfully logged out

  /auth/refresh:
    post:
      tags:
        - Authentication
      summary: Refresh authentication token
      responses:
        '200':
          description: Token refreshed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenResponse'

  /devices:
    get:
      tags:
        - Devices
      summary: List all devices with optional filtering
      parameters:
        - $ref: '#/components/parameters/PageSize'
        - $ref: '#/components/parameters/PageNumber'
        - $ref: '#/components/parameters/SortBy'
        - $ref: '#/components/parameters/FilterSite'
        - $ref: '#/components/parameters/FilterType'
        - $ref: '#/components/parameters/FilterSubType'
        - $ref: '#/components/parameters/FilterTag'
        - $ref: '#/components/parameters/FilterStatus'
      responses:
        '200':
          description: List of devices
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DeviceList'

    post:
      tags:
        - Devices
      summary: Add a new device
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DeviceCreate'
      responses:
        '201':
          description: Device created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Device'
        '409':
          description: Device already exists

  /devices/{deviceId}:
    get:
      tags:
        - Devices
      summary: Get device details
      parameters:
        - $ref: '#/components/parameters/DeviceId'
      responses:
        '200':
          description: Device details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Device'
        '404':
          description: Device not found

    put:
      tags:
        - Devices
      summary: Update device
      parameters:
        - $ref: '#/components/parameters/DeviceId'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DeviceUpdate'
      responses:
        '200':
          description: Device updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Device'

    delete:
      tags:
        - Devices
      summary: Delete device
      parameters:
        - $ref: '#/components/parameters/DeviceId'
      responses:
        '204':
          description: Device deleted
        '404':
          description: Device not found

  /devices/bulk:
    post:
      tags:
        - Devices
      summary: Bulk import devices
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
                format:
                  type: string
                  enum: [csv, json]
      responses:
        '200':
          description: Import results
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BulkImportResult'

  /devices/filter:
    post:
      tags:
        - Devices
      summary: Advanced device filtering
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DeviceFilter'
      responses:
        '200':
          description: Filtered devices
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DeviceList'

  /tasks/execute:
    post:
      tags:
        - Tasks
      summary: Execute task on devices
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TaskExecutionRequest'
      responses:
        '202':
          description: Task execution started
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TaskExecutionResponse'

  /tasks/{taskId}:
    get:
      tags:
        - Tasks
      summary: Get task status
      parameters:
        - $ref: '#/components/parameters/TaskId'
      responses:
        '200':
          description: Task status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TaskStatus'

  /tasks/{taskId}/output:
    get:
      tags:
        - Tasks
      summary: Get task output
      parameters:
        - $ref: '#/components/parameters/TaskId'
        - name: device_id
          in: query
          schema:
            type: integer
          description: Get output for specific device
      responses:
        '200':
          description: Task output
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TaskOutput'

  /tasks/history:
    get:
      tags:
        - Tasks
      summary: Get task execution history
      parameters:
        - $ref: '#/components/parameters/PageSize'
        - $ref: '#/components/parameters/PageNumber'
        - name: device_id
          in: query
          schema:
            type: integer
        - name: from_date
          in: query
          schema:
            type: string
            format: date-time
        - name: to_date
          in: query
          schema:
            type: string
            format: date-time
      responses:
        '200':
          description: Task history
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TaskHistoryList'

  /config/push:
    post:
      tags:
        - Configuration
      summary: Push configuration to devices
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConfigPushRequest'
      responses:
        '202':
          description: Configuration push started
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TaskExecutionResponse'

  /config/validate:
    post:
      tags:
        - Configuration
      summary: Validate configuration syntax
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConfigValidateRequest'
      responses:
        '200':
          description: Validation results
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ConfigValidationResult'

  /config/diff:
    post:
      tags:
        - Configuration
      summary: Generate configuration diff
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConfigDiffRequest'
      responses:
        '200':
          description: Configuration diff
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ConfigDiffResult'

  /ws/tasks:
    get:
      tags:
        - WebSocket
      summary: WebSocket endpoint for real-time task updates
      responses:
        '101':
          description: Switching Protocols

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  parameters:
    DeviceId:
      name: deviceId
      in: path
      required: true
      schema:
        type: integer
      description: Device ID

    TaskId:
      name: taskId
      in: path
      required: true
      schema:
        type: string
        format: uuid
      description: Task execution ID

    PageSize:
      name: page_size
      in: query
      schema:
        type: integer
        default: 20
        maximum: 100
      description: Number of items per page

    PageNumber:
      name: page
      in: query
      schema:
        type: integer
        default: 1
      description: Page number

    SortBy:
      name: sort_by
      in: query
      schema:
        type: string
        enum: [hostname, ip_address, site_name, device_type, last_seen]
      description: Sort field

    FilterSite:
      name: site
      in: query
      schema:
        type: string
      description: Filter by site name

    FilterType:
      name: type
      in: query
      schema:
        type: string
      description: Filter by device type

    FilterSubType:
      name: subtype
      in: query
      schema:
        type: string
      description: Filter by device sub-type

    FilterTag:
      name: tag
      in: query
      schema:
        type: string
      description: Filter by tag

    FilterStatus:
      name: status
      in: query
      schema:
        type: string
        enum: [active, inactive, maintenance]
      description: Filter by status

  schemas:
    LoginRequest:
      type: object
      required:
        - username
        - password
      properties:
        username:
          type: string
          example: john.doe
        password:
          type: string
          format: password
        remember_me:
          type: boolean
          default: false

    LoginResponse:
      type: object
      properties:
        token:
          type: string
        expires_at:
          type: string
          format: date-time
        user:
          $ref: '#/components/schemas/User'

    TokenResponse:
      type: object
      properties:
        token:
          type: string
        expires_at:
          type: string
          format: date-time

    User:
      type: object
      properties:
        username:
          type: string
        email:
          type: string
        groups:
          type: array
          items:
            type: string
        last_login:
          type: string
          format: date-time

    Device:
      type: object
      properties:
        id:
          type: integer
        hostname:
          type: string
        ip_address:
          type: string
        site_name:
          type: string
        device_type:
          type: string
        device_sub_type:
          type: string
        tags:
          type: array
          items:
            type: string
        sw_version:
          type: string
        model:
          type: string
        serial_number:
          type: string
        status:
          type: string
          enum: [active, inactive, maintenance]
        last_seen:
          type: string
          format: date-time
        last_backup:
          type: string
          format: date-time
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time

    DeviceCreate:
      type: object
      required:
        - hostname
        - ip_address
        - site_name
        - device_type
      properties:
        hostname:
          type: string
        ip_address:
          type: string
        site_name:
          type: string
        device_type:
          type: string
        device_sub_type:
          type: string
        tags:
          type: array
          items:
            type: string
        sw_version:
          type: string
        model:
          type: string
        serial_number:
          type: string

    DeviceUpdate:
      type: object
      properties:
        ip_address:
          type: string
        site_name:
          type: string
        device_type:
          type: string
        device_sub_type:
          type: string
        tags:
          type: array
          items:
            type: string
        sw_version:
          type: string
        model:
          type: string
        serial_number:
          type: string
        status:
          type: string
          enum: [active, inactive, maintenance]

    DeviceList:
      type: object
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/Device'
        total:
          type: integer
        page:
          type: integer
        page_size:
          type: integer

    DeviceFilter:
      type: object
      properties:
        filters:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
              operator:
                type: string
                enum: [eq, ne, contains, regex, in, not_in, gt, lt]
              value:
                oneOf:
                  - type: string
                  - type: array
                    items:
                      type: string
        logic:
          type: string
          enum: [AND, OR]
          default: AND

    BulkImportResult:
      type: object
      properties:
        total:
          type: integer
        successful:
          type: integer
        failed:
          type: integer
        errors:
          type: array
          items:
            type: object
            properties:
              line:
                type: integer
              hostname:
                type: string
              error:
                type: string

    TaskExecutionRequest:
      type: object
      required:
        - task_type
        - device_ids
      properties:
        task_type:
          type: string
          enum: [get_version, get_inventory, get_interfaces, get_config, 
                 get_routes, get_arp, get_mac, get_lldp_neighbors, 
                 get_logs, health_check, custom]
        device_ids:
          type: array
          items:
            type: integer
        parameters:
          type: object
          additionalProperties: true
        parallel:
          type: boolean
          default: true
        timeout:
          type: integer
          default: 60

    TaskExecutionResponse:
      type: object
      properties:
        task_id:
          type: string
          format: uuid
        status:
          type: string
          enum: [queued, running, completed, failed]
        device_count:
          type: integer
        started_at:
          type: string
          format: date-time

    TaskStatus:
      type: object
      properties:
        task_id:
          type: string
          format: uuid
        task_type:
          type: string
        status:
          type: string
          enum: [queued, running, completed, failed]
        progress:
          type: object
          properties:
            total:
              type: integer
            completed:
              type: integer
            failed:
              type: integer
        started_at:
          type: string
          format: date-time
        completed_at:
          type: string
          format: date-time
        devices:
          type: array
          items:
            type: object
            properties:
              device_id:
                type: integer
              hostname:
                type: string
              status:
                type: string
                enum: [pending, running, success, failed]
              error:
                type: string

    TaskOutput:
      type: object
      properties:
        task_id:
          type: string
          format: uuid
        outputs:
          type: array
          items:
            type: object
            properties:
              device_id:
                type: integer
              hostname:
                type: string
              output:
                type: string
              error:
                type: string
              execution_time:
                type: number

    TaskHistoryList:
      type: object
      properties:
        items:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              task_type:
                type: string
              task_name:
                type: string
              executed_by:
                type: string
              execution_time:
                type: string
                format: date-time
              status:
                type: string
              device_count:
                type: integer
        total:
          type: integer
        page:
          type: integer
        page_size:
          type: integer

    ConfigPushRequest:
      type: object
      required:
        - device_ids
        - commands
      properties:
        device_ids:
          type: array
          items:
            type: integer
        commands:
          type: array
          items:
            type: string
        mode:
          type: string
          enum: [set, delete]
          default: set
        commit:
          type: boolean
          default: true
        rollback_on_error:
          type: boolean
          default: true
        validate_only:
          type: boolean
          default: false

    ConfigValidateRequest:
      type: object
      required:
        - device_type
        - config
      properties:
        device_type:
          type: string
        config:
          type: array
          items:
            type: string

    ConfigValidationResult:
      type: object
      properties:
        valid:
          type: boolean
        errors:
          type: array
          items:
            type: object
            properties:
              line:
                type: integer
              command:
                type: string
              error:
                type: string

    ConfigDiffRequest:
      type: object
      required:
        - device_id
        - commands
      properties:
        device_id:
          type: integer
        commands:
          type: array
          items:
            type: string

    ConfigDiffResult:
      type: object
      properties:
        device_id:
          type: integer
        diff:
          type: string
        additions:
          type: array
          items:
            type: string
        deletions:
          type: array
          items:
            type: string
```

## Authentication Flow

### Login Process
1. Client sends POST to `/auth/login` with AD credentials
2. Server validates against AD using service account
3. Server creates session with encrypted credentials in memory
4. Server returns JWT token with session ID
5. Client includes token in Authorization header for all requests

### Session Management
- Sessions expire after 8 hours of inactivity
- Activity within 5 minutes of expiry auto-extends session
- Credentials remain encrypted in server memory
- Logout immediately clears credentials from memory

## Error Responses

All error responses follow RFC 7807 (Problem Details):

```json
{
  "type": "/errors/authentication-failed",
  "title": "Authentication Failed",
  "status": 401,
  "detail": "Invalid username or password",
  "instance": "/auth/login",
  "timestamp": "2024-01-15T10:30:00Z",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Standard Error Codes
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (resource already exists)
- `422` - Unprocessable Entity (validation failed)
- `423` - Locked (account locked)
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error
- `502` - Bad Gateway (upstream service error)
- `503` - Service Unavailable

## Rate Limiting

Rate limits are applied per user:
- Authentication: 5 attempts per 5 minutes
- API calls: 100 requests per minute
- Bulk operations: 10 per hour

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
```

## WebSocket Events

### Connection
```javascript
ws = new WebSocket('wss://api.network-automation.local/v1/ws/tasks');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'authenticate',
    token: 'jwt-token-here'
  }));
};
```

### Event Types

#### Task Progress
```json
{
  "type": "task.progress",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "progress": {
    "total": 10,
    "completed": 5,
    "failed": 1
  }
}
```

#### Device Output
```json
{
  "type": "device.output",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "device_id": 123,
  "hostname": "switch01.local",
  "output": "Cisco IOS Software, Version 15.2(7)E3\n...",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Task Complete
```json
{
  "type": "task.complete",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "summary": {
    "total": 10,
    "successful": 9,
    "failed": 1
  }
}
```

## Pagination

All list endpoints support pagination:
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 20, max: 100)

Response includes pagination metadata:
```json
{
  "items": [...],
  "total": 250,
  "page": 1,
  "page_size": 20,
  "total_pages": 13,
  "has_next": true,
  "has_previous": false
}
```

## Filtering

### Simple Filters
Query parameters for basic filtering:
```
GET /devices?site=HQ&type=cisco_ios&status=active
```

### Advanced Filters
POST to `/devices/filter` for complex queries:
```json
{
  "filters": [
    {
      "field": "site_name",
      "operator": "in",
      "value": ["HQ", "BRANCH1"]
    },
    {
      "field": "sw_version",
      "operator": "regex",
      "value": "15\\.2.*"
    }
  ],
  "logic": "AND"
}
```

## Versioning

API versioning is done through URL path:
- Current: `/v1/`
- Future: `/v2/`

Deprecation notices provided via headers:
```
Sunset: Sat, 31 Dec 2024 23:59:59 GMT
Deprecation: true
Link: <https://api.network-automation.local/v2>; rel="successor-version"
```

## Client SDK Examples

### Go Client
```go
client := NewClient("https://api.network-automation.local", token)
devices, err := client.Devices.List(DeviceFilters{
    Site: "HQ",
    Type: "cisco_ios",
})
```

### Python Client
```python
client = NetworkAutomationClient(
    base_url="https://api.network-automation.local",
    token=token
)
devices = client.devices.list(site="HQ", type="cisco_ios")
```

### curl Examples
```bash
# Login
curl -X POST https://api.network-automation.local/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john.doe","password":"secret"}'

# List devices
curl https://api.network-automation.local/v1/devices \
  -H "Authorization: Bearer <token>"

# Execute task
curl -X POST https://api.network-automation.local/v1/tasks/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "get_version",
    "device_ids": [1, 2, 3]
  }'
```
