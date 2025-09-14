package shutdown

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// ShutdownFunc represents a function to be called during shutdown
type ShutdownFunc func(ctx context.Context) error

// Manager manages graceful shutdown of the application
type Manager struct {
	logger      *zap.Logger
	shutdownFns []ShutdownFunc
	timeout     time.Duration
	mu          sync.Mutex
	shutdownCh  chan struct{}
	done        chan struct{}
	once        sync.Once
}

// NewManager creates a new shutdown manager
func NewManager(timeout time.Duration, logger *zap.Logger) *Manager {
	return &Manager{
		logger:      logger,
		shutdownFns: make([]ShutdownFunc, 0),
		timeout:     timeout,
		shutdownCh:  make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Register adds a shutdown function to be called during shutdown
func (m *Manager) Register(name string, fn ShutdownFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wrappedFn := func(ctx context.Context) error {
		m.logger.Info("Shutting down component", zap.String("component", name))
		start := time.Now()

		err := fn(ctx)
		duration := time.Since(start)

		if err != nil {
			m.logger.Error("Component shutdown failed",
				zap.String("component", name),
				zap.Duration("duration", duration),
				zap.Error(err))
		} else {
			m.logger.Info("Component shutdown completed",
				zap.String("component", name),
				zap.Duration("duration", duration))
		}

		return err
	}

	m.shutdownFns = append(m.shutdownFns, wrappedFn)
}

// Listen starts listening for shutdown signals
func (m *Manager) Listen() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		m.logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		m.Shutdown()
	}()
}

// Shutdown initiates graceful shutdown
func (m *Manager) Shutdown() {
	m.once.Do(func() {
		m.logger.Info("Starting graceful shutdown...")
		close(m.shutdownCh)

		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()

		// Execute shutdown functions in reverse order (LIFO)
		var wg sync.WaitGroup
		errors := make([]error, 0)
		errorsMu := sync.Mutex{}

		for i := len(m.shutdownFns) - 1; i >= 0; i-- {
			wg.Add(1)
			go func(fn ShutdownFunc) {
				defer wg.Done()
				if err := fn(ctx); err != nil {
					errorsMu.Lock()
					errors = append(errors, err)
					errorsMu.Unlock()
				}
			}(m.shutdownFns[i])
		}

		// Wait for all shutdown functions to complete or timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			if len(errors) > 0 {
				m.logger.Error("Some components failed to shutdown gracefully",
					zap.Int("error_count", len(errors)))
			} else {
				m.logger.Info("All components shut down successfully")
			}
		case <-ctx.Done():
			m.logger.Error("Shutdown timeout exceeded, forcing exit")
		}

		close(m.done)
	})
}

// Wait blocks until shutdown is complete
func (m *Manager) Wait() {
	<-m.done
}

// IsShuttingDown returns true if shutdown has been initiated
func (m *Manager) IsShuttingDown() bool {
	select {
	case <-m.shutdownCh:
		return true
	default:
		return false
	}
}

// ShutdownChannel returns a channel that is closed when shutdown begins
func (m *Manager) ShutdownChannel() <-chan struct{} {
	return m.shutdownCh
}

// ConnectionDrainer manages draining of active connections
type ConnectionDrainer struct {
	activeConnections int64
	mu                sync.RWMutex
	draining          bool
	logger            *zap.Logger
}

// NewConnectionDrainer creates a new connection drainer
func NewConnectionDrainer(logger *zap.Logger) *ConnectionDrainer {
	return &ConnectionDrainer{
		logger: logger,
	}
}

// AddConnection increments the active connection count
func (cd *ConnectionDrainer) AddConnection() bool {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if cd.draining {
		return false // Don't accept new connections during shutdown
	}

	cd.activeConnections++
	return true
}

// RemoveConnection decrements the active connection count
func (cd *ConnectionDrainer) RemoveConnection() {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if cd.activeConnections > 0 {
		cd.activeConnections--
	}
}

// GetActiveCount returns the current number of active connections
func (cd *ConnectionDrainer) GetActiveCount() int64 {
	cd.mu.RLock()
	defer cd.mu.RUnlock()
	return cd.activeConnections
}

// StartDraining begins the connection draining process
func (cd *ConnectionDrainer) StartDraining() {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.draining = true
	cd.logger.Info("Started connection draining")
}

// IsDraining returns true if connection draining is active
func (cd *ConnectionDrainer) IsDraining() bool {
	cd.mu.RLock()
	defer cd.mu.RUnlock()
	return cd.draining
}

// WaitForDrain waits for all connections to drain with a timeout
func (cd *ConnectionDrainer) WaitForDrain(ctx context.Context) error {
	cd.StartDraining()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			remaining := cd.GetActiveCount()
			if remaining > 0 {
				return fmt.Errorf("connection draining timeout: %d connections remaining", remaining)
			}
			return nil
		case <-ticker.C:
			count := cd.GetActiveCount()
			if count == 0 {
				cd.logger.Info("All connections drained successfully")
				return nil
			}
			cd.logger.Debug("Waiting for connections to drain",
				zap.Int64("remaining", count))
		}
	}
}

// HTTPConnectionMiddleware returns middleware that tracks HTTP connections
func (cd *ConnectionDrainer) HTTPConnectionMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if we're draining connections
			if !cd.AddConnection() {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("Service is shutting down"))
				return
			}
			defer cd.RemoveConnection()

			next.ServeHTTP(w, r)
		})
	}
}

// ResourceManager manages cleanup of various resources
type ResourceManager struct {
	resources map[string]func() error
	mu        sync.RWMutex
	logger    *zap.Logger
}

// NewResourceManager creates a new resource manager
func NewResourceManager(logger *zap.Logger) *ResourceManager {
	return &ResourceManager{
		resources: make(map[string]func() error),
		logger:    logger,
	}
}

// RegisterResource registers a resource for cleanup
func (rm *ResourceManager) RegisterResource(name string, cleanupFn func() error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.resources[name] = cleanupFn
}

// CleanupAll cleans up all registered resources
func (rm *ResourceManager) CleanupAll(ctx context.Context) error {
	rm.mu.RLock()
	resources := make(map[string]func() error)
	for name, fn := range rm.resources {
		resources[name] = fn
	}
	rm.mu.RUnlock()

	var wg sync.WaitGroup
	errors := make([]error, 0)
	errorsMu := sync.Mutex{}

	for name, cleanupFn := range resources {
		wg.Add(1)
		go func(resourceName string, fn func() error) {
			defer wg.Done()

			rm.logger.Info("Cleaning up resource", zap.String("resource", resourceName))
			if err := fn(); err != nil {
				rm.logger.Error("Failed to cleanup resource",
					zap.String("resource", resourceName),
					zap.Error(err))
				errorsMu.Lock()
				errors = append(errors, fmt.Errorf("cleanup %s: %w", resourceName, err))
				errorsMu.Unlock()
			} else {
				rm.logger.Info("Resource cleaned up successfully",
					zap.String("resource", resourceName))
			}
		}(name, cleanupFn)
	}

	// Wait for cleanup completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if len(errors) > 0 {
			return fmt.Errorf("resource cleanup errors: %v", errors)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("resource cleanup timeout")
	}
}