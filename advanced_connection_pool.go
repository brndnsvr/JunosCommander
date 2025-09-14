// Advanced SSH Connection Pool for Production Network Operations
// Supports 100+ concurrent connections with device-specific optimizations

package ssh

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ConnectionPool manages SSH connections with intelligent load balancing
type ConnectionPool struct {
	mu               sync.RWMutex
	devicePools      map[string]*DevicePool
	globalStats      *PoolStatistics
	config           PoolConfig
	circuitBreaker   *CircuitBreaker
	healthChecker    *HealthChecker
	metrics          MetricsCollector
	logger           Logger
	shutdownChan     chan struct{}
	wg               sync.WaitGroup
}

// DevicePool manages connections for a specific device with quirks handling
type DevicePool struct {
	device           *NetworkDevice
	connections      chan *SSHConnection
	activeConns      map[string]*SSHConnection
	connectionCount  int64
	failureCount     int64
	lastFailure      time.Time
	quirks           *DeviceQuirks
	stats            *DeviceStatistics
	healthStatus     HealthStatus
	mu               sync.RWMutex
}

// SSHConnection wraps ssh.Client with connection metadata and optimizations
type SSHConnection struct {
	client          *ssh.Client
	session         *ssh.Session
	device          *NetworkDevice
	connectionID    string
	createdAt       time.Time
	lastUsed        time.Time
	useCount        int64
	isHealthy       bool
	configMode      bool
	privilege       PrivilegeLevel
	capabilities    DeviceCapabilities
	commandCache    *CommandCache
	mu              sync.RWMutex
}

// NetworkDevice represents a network device with connection parameters
type NetworkDevice struct {
	ID              int
	Hostname        string
	IPAddress       string
	Port            int
	DeviceType      string
	Vendor          string
	Model           string
	Version         string
	Features        []string
	ConnectionInfo  ConnectionInfo
	Credentials     *Credentials
}

// DeviceQuirks handles device-specific connection behaviors
type DeviceQuirks struct {
	LoginBanner         string
	PromptPattern       string
	EnableCommand       string
	ConfigModeCommand   string
	ExitCommand         string
	SaveCommand         string
	MaxConcurrent       int
	CommandDelay        time.Duration
	SessionTimeout      time.Duration
	KeepAliveInterval   time.Duration
	ReconnectDelay      time.Duration
	RequiresPrivileged  bool
	SupportsNetconf     bool
}

// DeviceCapabilities tracks what the device supports
type DeviceCapabilities struct {
	SupportsCommitConfirm bool
	SupportsRollback      bool
	SupportsCompare       bool
	SupportsLoadMerge     bool
	MaxConfigSize         int64
	ConcurrentSessions    int
	Features              map[string]bool
}

// PoolConfig holds connection pool configuration
type PoolConfig struct {
	MaxConnectionsPerDevice    int
	MaxTotalConnections       int
	ConnectionTimeout         time.Duration
	IdleTimeout               time.Duration
	HealthCheckInterval       time.Duration
	ReconnectRetries          int
	CircuitBreakerThreshold   int
	EnableConnectionReuse     bool
	EnableCommandCaching      bool
	MetricsInterval           time.Duration
}

// PoolStatistics tracks overall pool performance
type PoolStatistics struct {
	TotalConnections     int64
	ActiveConnections    int64
	FailedConnections    int64
	CacheHits            int64
	CacheMisses          int64
	AverageConnectTime   time.Duration
	AverageCommandTime   time.Duration
	CircuitBreakerTrips  int64
}

// DeviceStatistics tracks per-device performance
type DeviceStatistics struct {
	ConnectionAttempts   int64
	SuccessfulConnects   int64
	FailedConnects       int64
	CommandsExecuted     int64
	AverageLatency       time.Duration
	LastSuccessfulConnect time.Time
	LastError            error
}

// CommandCache provides intelligent command result caching
type CommandCache struct {
	cache     map[string]*CacheEntry
	maxSize   int
	ttl       time.Duration
	mu        sync.RWMutex
}

// CacheEntry represents a cached command result
type CacheEntry struct {
	Command   string
	Result    string
	Error     error
	Timestamp time.Time
	Hash      string
}

// NewConnectionPool creates a new advanced connection pool
func NewConnectionPool(config PoolConfig, logger Logger, metrics MetricsCollector) *ConnectionPool {
	pool := &ConnectionPool{
		devicePools:    make(map[string]*DevicePool),
		globalStats:    &PoolStatistics{},
		config:         config,
		circuitBreaker: NewCircuitBreaker(config.CircuitBreakerThreshold),
		healthChecker:  NewHealthChecker(config.HealthCheckInterval),
		metrics:        metrics,
		logger:         logger,
		shutdownChan:   make(chan struct{}),
	}

	// Start background maintenance routines
	pool.startMaintenanceRoutines()

	return pool
}

// GetConnection retrieves a connection with intelligent load balancing
func (p *ConnectionPool) GetConnection(ctx context.Context, device *NetworkDevice, creds *Credentials) (*SSHConnection, error) {
	deviceKey := fmt.Sprintf("%s:%d", device.IPAddress, device.Port)

	// Check circuit breaker
	if !p.circuitBreaker.AllowRequest(deviceKey) {
		return nil, fmt.Errorf("circuit breaker open for device %s", device.Hostname)
	}

	// Get or create device pool
	devicePool, err := p.getOrCreateDevicePool(device)
	if err != nil {
		return nil, fmt.Errorf("failed to get device pool: %w", err)
	}

	// Try to get existing connection first
	if conn := p.tryReuseConnection(devicePool); conn != nil {
		return conn, nil
	}

	// Create new connection if under limits
	conn, err := p.createNewConnection(ctx, devicePool, creds)
	if err != nil {
		p.circuitBreaker.RecordFailure(deviceKey)
		atomic.AddInt64(&devicePool.failureCount, 1)
		devicePool.lastFailure = time.Now()

		p.logger.Error("Failed to create connection",
			"device", device.Hostname,
			"error", err,
		)
		return nil, err
	}

	p.circuitBreaker.RecordSuccess(deviceKey)
	atomic.AddInt64(&p.globalStats.ActiveConnections, 1)

	return conn, nil
}

// getOrCreateDevicePool gets or creates a device pool with quirks detection
func (p *ConnectionPool) getOrCreateDevicePool(device *NetworkDevice) (*DevicePool, error) {
	deviceKey := fmt.Sprintf("%s:%d", device.IPAddress, device.Port)

	p.mu.RLock()
	if pool, exists := p.devicePools[deviceKey]; exists {
		p.mu.RUnlock()
		return pool, nil
	}
	p.mu.RUnlock()

	// Create new device pool with double-checked locking
	p.mu.Lock()
	defer p.mu.Unlock()

	if pool, exists := p.devicePools[deviceKey]; exists {
		return pool, nil
	}

	// Detect device quirks
	quirks := p.detectDeviceQuirks(device)

	// Create device pool
	devicePool := &DevicePool{
		device:       device,
		connections:  make(chan *SSHConnection, p.config.MaxConnectionsPerDevice),
		activeConns:  make(map[string]*SSHConnection),
		quirks:       quirks,
		stats:        &DeviceStatistics{},
		healthStatus: HealthStatusUnknown,
	}

	p.devicePools[deviceKey] = devicePool
	return devicePool, nil
}

// detectDeviceQuirks identifies device-specific behaviors
func (p *ConnectionPool) detectDeviceQuirks(device *NetworkDevice) *DeviceQuirks {
	quirks := &DeviceQuirks{
		MaxConcurrent:     p.config.MaxConnectionsPerDevice,
		CommandDelay:      50 * time.Millisecond,
		SessionTimeout:    30 * time.Minute,
		KeepAliveInterval: 30 * time.Second,
		ReconnectDelay:    5 * time.Second,
	}

	// Juniper-specific optimizations
	if device.Vendor == "juniper" || device.DeviceType == "junos" {
		quirks.PromptPattern = `[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+[>#%] ?`
		quirks.ConfigModeCommand = "configure"
		quirks.ExitCommand = "exit"
		quirks.SaveCommand = "commit and-quit"
		quirks.SupportsNetconf = true
		quirks.MaxConcurrent = 8 // Junos typically supports more concurrent sessions

		// Version-specific optimizations
		if device.Version != "" {
			if p.isJunosVersionAtLeast(device.Version, "15.1") {
				quirks.SupportsNetconf = true
			}
			if p.isJunosVersionAtLeast(device.Version, "18.1") {
				quirks.MaxConcurrent = 10
			}
		}
	}

	// Cisco-specific optimizations
	if device.Vendor == "cisco" {
		quirks.PromptPattern = `[a-zA-Z0-9\-_]+[>#] ?`
		quirks.EnableCommand = "enable"
		quirks.ConfigModeCommand = "configure terminal"
		quirks.ExitCommand = "exit"
		quirks.SaveCommand = "write memory"
		quirks.RequiresPrivileged = true
		quirks.MaxConcurrent = 5 // Cisco devices typically have lower limits
	}

	// Arista-specific optimizations
	if device.Vendor == "arista" {
		quirks.PromptPattern = `[a-zA-Z0-9\-_]+[>#] ?`
		quirks.ConfigModeCommand = "configure"
		quirks.ExitCommand = "exit"
		quirks.SaveCommand = "write memory"
		quirks.MaxConcurrent = 6
	}

	return quirks
}

// tryReuseConnection attempts to reuse an existing connection
func (p *ConnectionPool) tryReuseConnection(devicePool *DevicePool) *SSHConnection {
	select {
	case conn := <-devicePool.connections:
		// Validate connection is still healthy
		if p.validateConnection(conn) {
			conn.mu.Lock()
			conn.lastUsed = time.Now()
			atomic.AddInt64(&conn.useCount, 1)
			conn.mu.Unlock()

			atomic.AddInt64(&p.globalStats.CacheHits, 1)
			return conn
		}

		// Connection is unhealthy, close it
		p.closeConnection(conn)

	default:
		// No connections available
	}

	atomic.AddInt64(&p.globalStats.CacheMisses, 1)
	return nil
}

// createNewConnection creates a new SSH connection with device-specific setup
func (p *ConnectionPool) createNewConnection(ctx context.Context, devicePool *DevicePool, creds *Credentials) (*SSHConnection, error) {
	startTime := time.Now()

	// Check concurrent connection limit
	if atomic.LoadInt64(&devicePool.connectionCount) >= int64(devicePool.quirks.MaxConcurrent) {
		return nil, fmt.Errorf("maximum concurrent connections reached for device %s", devicePool.device.Hostname)
	}

	// Prepare SSH client config with device-specific optimizations
	sshConfig := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            p.buildAuthMethods(creds),
		HostKeyCallback: p.buildHostKeyCallback(devicePool.device),
		Timeout:         p.config.ConnectionTimeout,
		BannerCallback:  p.buildBannerCallback(devicePool.quirks),
	}

	// Add device-specific client configuration
	p.configureSSHClient(sshConfig, devicePool.device, devicePool.quirks)

	// Create connection with context timeout
	conn, err := p.dialWithContext(ctx, devicePool.device, sshConfig)
	if err != nil {
		atomic.AddInt64(&devicePool.stats.FailedConnects, 1)
		return nil, fmt.Errorf("failed to connect to %s: %w", devicePool.device.Hostname, err)
	}

	// Create session
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Set up session with device-specific configurations
	if err := p.configureSession(session, devicePool.quirks); err != nil {
		session.Close()
		conn.Close()
		return nil, fmt.Errorf("failed to configure session: %w", err)
	}

	// Create connection wrapper
	connectionID := fmt.Sprintf("%s-%d", devicePool.device.Hostname, time.Now().UnixNano())
	sshConn := &SSHConnection{
		client:       conn,
		session:      session,
		device:       devicePool.device,
		connectionID: connectionID,
		createdAt:    time.Now(),
		lastUsed:     time.Now(),
		useCount:     1,
		isHealthy:    true,
		configMode:   false,
		privilege:    PrivilegeLevelUser,
		capabilities: p.detectCapabilities(devicePool.device),
		commandCache: NewCommandCache(100, 5*time.Minute), // 100 entries, 5 minute TTL
	}

	// Perform initial device setup and privilege escalation if needed
	if err := p.performInitialSetup(sshConn, creds); err != nil {
		p.closeConnection(sshConn)
		return nil, fmt.Errorf("failed initial setup: %w", err)
	}

	// Record connection statistics
	atomic.AddInt64(&devicePool.connectionCount, 1)
	atomic.AddInt64(&devicePool.stats.SuccessfulConnects, 1)
	devicePool.stats.LastSuccessfulConnect = time.Now()

	connectTime := time.Since(startTime)
	p.updateConnectionTime(connectTime)

	// Store in active connections
	devicePool.mu.Lock()
	devicePool.activeConns[connectionID] = sshConn
	devicePool.mu.Unlock()

	p.logger.Debug("Created new SSH connection",
		"device", devicePool.device.Hostname,
		"connection_id", connectionID,
		"connect_time", connectTime,
	)

	return sshConn, nil
}

// performInitialSetup handles device-specific initialization
func (p *ConnectionPool) performInitialSetup(conn *SSHConnection, creds *Credentials) error {
	// Handle login banner and initial prompts
	if err := p.handleLoginBanner(conn); err != nil {
		return fmt.Errorf("failed to handle login banner: %w", err)
	}

	// Escalate privileges if required
	if conn.device.Vendor == "cisco" || conn.device.DeviceType == "ios" {
		if err := p.escalatePrivileges(conn, creds); err != nil {
			return fmt.Errorf("failed to escalate privileges: %w", err)
		}
	}

	// Set terminal settings for optimal operation
	if err := p.setTerminalSettings(conn); err != nil {
		return fmt.Errorf("failed to set terminal settings: %w", err)
	}

	// Test basic connectivity
	if err := p.testBasicConnectivity(conn); err != nil {
		return fmt.Errorf("basic connectivity test failed: %w", err)
	}

	return nil
}

// ReturnConnection returns a connection to the pool
func (p *ConnectionPool) ReturnConnection(conn *SSHConnection) {
	if conn == nil {
		return
	}

	deviceKey := fmt.Sprintf("%s:%d", conn.device.IPAddress, conn.device.Port)

	p.mu.RLock()
	devicePool, exists := p.devicePools[deviceKey]
	p.mu.RUnlock()

	if !exists {
		p.closeConnection(conn)
		return
	}

	conn.mu.Lock()
	conn.lastUsed = time.Now()

	// Exit configuration mode if in it
	if conn.configMode {
		p.exitConfigMode(conn)
	}
	conn.mu.Unlock()

	// Check if connection should be returned to pool
	if p.shouldReuseConnection(conn) {
		select {
		case devicePool.connections <- conn:
			// Successfully returned to pool
			return
		default:
			// Pool is full, close connection
		}
	}

	// Close connection if not reusable
	p.closeConnection(conn)
}

// shouldReuseConnection determines if a connection should be reused
func (p *ConnectionPool) shouldReuseConnection(conn *SSHConnection) bool {
	if !p.config.EnableConnectionReuse {
		return false
	}

	conn.mu.RLock()
	defer conn.mu.RUnlock()

	// Check health status
	if !conn.isHealthy {
		return false
	}

	// Check age limit
	if time.Since(conn.createdAt) > p.config.IdleTimeout {
		return false
	}

	// Check usage count
	if conn.useCount > 1000 { // Rotate connections after 1000 uses
		return false
	}

	return true
}

// ExecuteCommand executes a command with caching and error handling
func (p *ConnectionPool) ExecuteCommand(ctx context.Context, conn *SSHConnection, command string) (*CommandResult, error) {
	// Check command cache first
	if p.config.EnableCommandCaching {
		if cached := conn.commandCache.Get(command); cached != nil {
			return &CommandResult{
				Command:   command,
				Output:    cached.Result,
				Error:     cached.Error,
				Duration:  0, // Cached result
				Cached:    true,
				Timestamp: cached.Timestamp,
			}, cached.Error
		}
	}

	startTime := time.Now()
	result, err := p.executeCommandWithTimeout(ctx, conn, command)
	duration := time.Since(startTime)

	commandResult := &CommandResult{
		Command:   command,
		Output:    result,
		Error:     err,
		Duration:  duration,
		Cached:    false,
		Timestamp: time.Now(),
	}

	// Cache result if cacheable
	if p.config.EnableCommandCaching && p.isCacheable(command) {
		conn.commandCache.Set(command, result, err)
	}

	// Update statistics
	atomic.AddInt64(&conn.device.ConnectionInfo.CommandsExecuted, 1)
	p.updateCommandTime(duration)

	return commandResult, err
}

// executeCommandWithTimeout executes a command with proper timeout handling
func (p *ConnectionPool) executeCommandWithTimeout(ctx context.Context, conn *SSHConnection, command string) (string, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Create command context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Execute command with device-specific handling
	return p.executeDeviceSpecificCommand(cmdCtx, conn, command)
}

// Close gracefully closes the connection pool
func (p *ConnectionPool) Close() error {
	p.logger.Info("Shutting down connection pool")

	close(p.shutdownChan)
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Close all device pools
	for _, devicePool := range p.devicePools {
		p.closeDevicePool(devicePool)
	}

	return nil
}

// Additional helper methods and structures would continue...

// CommandResult represents the result of a command execution
type CommandResult struct {
	Command   string
	Output    string
	Error     error
	Duration  time.Duration
	Cached    bool
	Timestamp time.Time
}

// PrivilegeLevel represents the current privilege level
type PrivilegeLevel int

const (
	PrivilegeLevelUser PrivilegeLevel = iota
	PrivilegeLevelPrivileged
	PrivilegeLevelConfig
)

// HealthStatus represents device health status
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusWarning
	HealthStatusUnhealthy
)

// ConnectionInfo holds connection metadata
type ConnectionInfo struct {
	ConnectedAt      time.Time
	LastActivity     time.Time
	CommandsExecuted int64
	BytesTransmitted int64
	BytesReceived    int64
}