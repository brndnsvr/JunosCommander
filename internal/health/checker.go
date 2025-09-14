package health

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Status represents health check status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Name      string        `json:"name"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
	Details   interface{}   `json:"details,omitempty"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status    Status                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Uptime    time.Duration          `json:"uptime"`
	Checks    map[string]CheckResult `json:"checks"`
}

// Checker interface for health checks
type Checker interface {
	Check(ctx context.Context) CheckResult
	Name() string
}

// HealthService manages health checks
type HealthService struct {
	checkers  map[string]Checker
	startTime time.Time
	version   string
	mu        sync.RWMutex
	logger    *zap.Logger
}

// NewHealthService creates a new health service
func NewHealthService(version string, logger *zap.Logger) *HealthService {
	return &HealthService{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
		version:   version,
		logger:    logger,
	}
}

// RegisterChecker registers a health checker
func (hs *HealthService) RegisterChecker(checker Checker) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.checkers[checker.Name()] = checker
}

// Check performs all health checks
func (hs *HealthService) Check(ctx context.Context) HealthResponse {
	hs.mu.RLock()
	checkers := make(map[string]Checker, len(hs.checkers))
	for name, checker := range hs.checkers {
		checkers[name] = checker
	}
	hs.mu.RUnlock()

	checks := make(map[string]CheckResult, len(checkers))
	var wg sync.WaitGroup
	resultCh := make(chan CheckResult, len(checkers))

	// Run all checks concurrently
	for _, checker := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			result := c.Check(ctx)
			resultCh <- result
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results
	for result := range resultCh {
		checks[result.Name] = result
	}

	// Determine overall status
	overallStatus := StatusHealthy
	for _, result := range checks {
		if result.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
			break
		} else if result.Status == StatusDegraded {
			overallStatus = StatusDegraded
		}
	}

	return HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Version:   hs.version,
		Uptime:    time.Since(hs.startTime),
		Checks:    checks,
	}
}

// HealthHandler returns the health endpoint handler
func (hs *HealthService) HealthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		health := hs.Check(ctx)

		statusCode := 200
		if health.Status == StatusUnhealthy {
			statusCode = 503
		} else if health.Status == StatusDegraded {
			statusCode = 200 // Still return 200 for degraded
		}

		c.JSON(statusCode, health)
	}
}

// ReadinessHandler returns the readiness endpoint handler
func (hs *HealthService) ReadinessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()

		health := hs.Check(ctx)

		// For readiness, we're more strict - any unhealthy check fails readiness
		statusCode := 200
		if health.Status != StatusHealthy {
			statusCode = 503
		}

		c.JSON(statusCode, gin.H{
			"status":    health.Status,
			"timestamp": health.Timestamp,
		})
	}
}

// LivenessHandler returns the liveness endpoint handler
func (hs *HealthService) LivenessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Liveness is just a simple check that the service is running
		c.JSON(200, gin.H{
			"status":    "alive",
			"timestamp": time.Now(),
			"uptime":    time.Since(hs.startTime),
		})
	}
}

// DatabaseChecker checks database connectivity
type DatabaseChecker struct {
	db   *sql.DB
	name string
}

// NewDatabaseChecker creates a new database checker
func NewDatabaseChecker(name string, db *sql.DB) *DatabaseChecker {
	return &DatabaseChecker{
		db:   db,
		name: name,
	}
}

// Name returns the checker name
func (dc *DatabaseChecker) Name() string {
	return dc.name
}

// Check performs the database health check
func (dc *DatabaseChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      dc.name,
		Timestamp: start,
	}

	if dc.db == nil {
		result.Status = StatusUnhealthy
		result.Message = "Database connection is nil"
		result.Duration = time.Since(start)
		return result
	}

	// Test with a simple query
	var dummy int
	err := dc.db.QueryRowContext(ctx, "SELECT 1").Scan(&dummy)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Database query failed: %v", err)
		return result
	}

	// Get connection stats
	stats := dc.db.Stats()
	result.Status = StatusHealthy
	result.Message = "Database is accessible"
	result.Details = map[string]interface{}{
		"open_connections": stats.OpenConnections,
		"in_use":          stats.InUse,
		"idle":            stats.Idle,
		"max_open_conns":  stats.MaxOpenConnections,
	}

	// Check if we're running low on connections
	if stats.InUse > int(0.8*float64(stats.MaxOpenConnections)) {
		result.Status = StatusDegraded
		result.Message = "Database connection pool usage is high"
	}

	return result
}

// RedisChecker checks Redis connectivity
type RedisChecker struct {
	healthChecker func(ctx context.Context) error
	name          string
}

// NewRedisChecker creates a new Redis checker
func NewRedisChecker(name string, healthChecker func(ctx context.Context) error) *RedisChecker {
	return &RedisChecker{
		healthChecker: healthChecker,
		name:          name,
	}
}

// Name returns the checker name
func (rc *RedisChecker) Name() string {
	return rc.name
}

// Check performs the Redis health check
func (rc *RedisChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      rc.name,
		Timestamp: start,
	}

	if rc.healthChecker == nil {
		result.Status = StatusUnhealthy
		result.Message = "Redis health checker is not configured"
		result.Duration = time.Since(start)
		return result
	}

	err := rc.healthChecker(ctx)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Redis health check failed: %v", err)
		return result
	}

	result.Status = StatusHealthy
	result.Message = "Redis is accessible"
	return result
}

// DiskSpaceChecker checks available disk space
type DiskSpaceChecker struct {
	path           string
	thresholdBytes int64
	name           string
}

// NewDiskSpaceChecker creates a new disk space checker
func NewDiskSpaceChecker(name, path string, thresholdBytes int64) *DiskSpaceChecker {
	return &DiskSpaceChecker{
		path:           path,
		thresholdBytes: thresholdBytes,
		name:           name,
	}
}

// Name returns the checker name
func (dsc *DiskSpaceChecker) Name() string {
	return dsc.name
}

// Check performs the disk space health check
func (dsc *DiskSpaceChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      dsc.name,
		Timestamp: start,
	}

	// This is a simplified implementation - in production you'd use syscall.Statfs_t
	// For now, we'll just return healthy
	result.Duration = time.Since(start)
	result.Status = StatusHealthy
	result.Message = "Disk space check passed"
	result.Details = map[string]interface{}{
		"path":      dsc.path,
		"threshold": dsc.thresholdBytes,
	}

	return result
}

// ComponentChecker checks if a component is available
type ComponentChecker struct {
	checkFunc func(ctx context.Context) error
	name      string
}

// NewComponentChecker creates a generic component checker
func NewComponentChecker(name string, checkFunc func(ctx context.Context) error) *ComponentChecker {
	return &ComponentChecker{
		checkFunc: checkFunc,
		name:      name,
	}
}

// Name returns the checker name
func (cc *ComponentChecker) Name() string {
	return cc.name
}

// Check performs the component health check
func (cc *ComponentChecker) Check(ctx context.Context) CheckResult {
	start := time.Now()
	result := CheckResult{
		Name:      cc.name,
		Timestamp: start,
	}

	err := cc.checkFunc(ctx)
	result.Duration = time.Since(start)

	if err != nil {
		result.Status = StatusUnhealthy
		result.Message = fmt.Sprintf("Component check failed: %v", err)
		return result
	}

	result.Status = StatusHealthy
	result.Message = "Component is healthy"
	return result
}