package ssh

import (
	"fmt"
	"sync"
	"time"

	"github.com/junoscommander/junoscommander/internal/config"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// ConnectionPool manages SSH connections to devices
type ConnectionPool struct {
	config *config.SSHConfig
	logger *zap.Logger
	mu     sync.RWMutex
	pools  map[string]*DevicePool
}

// DevicePool manages connections for a single device
type DevicePool struct {
	hostname    string
	ipAddress   string
	connections chan *Connection
	mu          sync.Mutex
	creating    int
	maxSize     int
}

// Connection represents an SSH connection
type Connection struct {
	client   *ssh.Client
	hostname string
	inUse    bool
	lastUsed time.Time
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(cfg *config.SSHConfig, logger *zap.Logger) *ConnectionPool {
	return &ConnectionPool{
		config: cfg,
		logger: logger,
		pools:  make(map[string]*DevicePool),
	}
}

// GetConnection gets or creates a connection to a device
func (p *ConnectionPool) GetConnection(hostname, ipAddress, username, password string) (*Connection, error) {
	p.mu.Lock()
	devicePool, exists := p.pools[hostname]
	if !exists {
		devicePool = &DevicePool{
			hostname:    hostname,
			ipAddress:   ipAddress,
			connections: make(chan *Connection, p.config.ConnectionPoolSize),
			maxSize:     p.config.ConnectionPoolSize,
		}
		p.pools[hostname] = devicePool
	}
	p.mu.Unlock()

	// Try to get an existing connection
	select {
	case conn := <-devicePool.connections:
		if conn.client != nil {
			// Test if connection is still alive
			session, err := conn.client.NewSession()
			if err == nil {
				session.Close()
				conn.inUse = true
				conn.lastUsed = time.Now()
				return conn, nil
			}
			// Connection is dead, close it
			conn.client.Close()
		}
	default:
		// No available connections
	}

	// Create new connection
	return p.createConnection(hostname, ipAddress, username, password)
}

// createConnection creates a new SSH connection
func (p *ConnectionPool) createConnection(hostname, ipAddress, username, password string) (*Connection, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
		Timeout:         p.config.DefaultTimeout,
	}

	// Connect to device
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ipAddress), config)
	if err != nil {
		p.logger.Error("Failed to connect to device",
			zap.String("hostname", hostname),
			zap.String("ip", ipAddress),
			zap.Error(err))
		return nil, fmt.Errorf("failed to connect to %s: %w", hostname, err)
	}

	conn := &Connection{
		client:   client,
		hostname: hostname,
		inUse:    true,
		lastUsed: time.Now(),
	}

	p.logger.Debug("Created new SSH connection",
		zap.String("hostname", hostname),
		zap.String("ip", ipAddress))

	return conn, nil
}

// ReturnConnection returns a connection to the pool
func (p *ConnectionPool) ReturnConnection(conn *Connection) {
	if conn == nil || conn.client == nil {
		return
	}

	p.mu.RLock()
	devicePool, exists := p.pools[conn.hostname]
	p.mu.RUnlock()

	if !exists {
		// Pool doesn't exist, close the connection
		conn.client.Close()
		return
	}

	conn.inUse = false
	conn.lastUsed = time.Now()

	// Try to return to pool
	select {
	case devicePool.connections <- conn:
		// Connection returned to pool
	default:
		// Pool is full, close the connection
		conn.client.Close()
	}
}

// ExecuteCommand executes a command on a connection
func (c *Connection) ExecuteCommand(command string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Execute command
	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, devicePool := range p.pools {
		close(devicePool.connections)
		for conn := range devicePool.connections {
			if conn.client != nil {
				conn.client.Close()
			}
		}
	}

	p.pools = make(map[string]*DevicePool)
}