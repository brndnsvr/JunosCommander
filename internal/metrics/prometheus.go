package metrics

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Metrics holds all Prometheus metrics
type Metrics struct {
	// HTTP metrics
	httpRequestsTotal     *prometheus.CounterVec
	httpRequestDuration   *prometheus.HistogramVec
	httpRequestsInFlight  prometheus.Gauge

	// Application metrics
	activeSSHConnections  prometheus.Gauge
	sshConnectionsTotal   *prometheus.CounterVec
	taskExecutionTotal    *prometheus.CounterVec
	taskExecutionDuration *prometheus.HistogramVec
	taskQueueSize         prometheus.Gauge

	// Authentication metrics
	authAttemptsTotal     *prometheus.CounterVec
	activeSessionsCount   prometheus.Gauge

	// Database metrics
	dbConnectionsActive   prometheus.Gauge
	dbConnectionsIdle     prometheus.Gauge
	dbConnectionsTotal    prometheus.Gauge
	dbQueriesTotal        *prometheus.CounterVec
	dbQueryDuration       *prometheus.HistogramVec

	// Redis metrics
	redisConnectionsActive prometheus.Gauge
	redisOperationsTotal   *prometheus.CounterVec
	redisOperationDuration *prometheus.HistogramVec

	// System metrics
	applicationInfo       *prometheus.GaugeVec
	uptime               prometheus.Gauge
	startTime            time.Time

	logger *zap.Logger
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics(logger *zap.Logger) *Metrics {
	m := &Metrics{
		// HTTP metrics
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "junoscommander_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		httpRequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		}),

		// Application metrics
		activeSSHConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_ssh_connections_active",
			Help: "Number of active SSH connections",
		}),
		sshConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_ssh_connections_total",
				Help: "Total number of SSH connection attempts",
			},
			[]string{"device_type", "status"},
		),
		taskExecutionTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_task_executions_total",
				Help: "Total number of task executions",
			},
			[]string{"task_type", "status"},
		),
		taskExecutionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "junoscommander_task_execution_duration_seconds",
				Help:    "Task execution duration in seconds",
				Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0},
			},
			[]string{"task_type"},
		),
		taskQueueSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_task_queue_size",
			Help: "Current number of tasks in queue",
		}),

		// Authentication metrics
		authAttemptsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_auth_attempts_total",
				Help: "Total number of authentication attempts",
			},
			[]string{"method", "result"},
		),
		activeSessionsCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_active_sessions",
			Help: "Number of active user sessions",
		}),

		// Database metrics
		dbConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_db_connections_active",
			Help: "Number of active database connections",
		}),
		dbConnectionsIdle: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_db_connections_idle",
			Help: "Number of idle database connections",
		}),
		dbConnectionsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_db_connections_total",
			Help: "Total number of database connections",
		}),
		dbQueriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_db_queries_total",
				Help: "Total number of database queries",
			},
			[]string{"operation", "status"},
		),
		dbQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "junoscommander_db_query_duration_seconds",
				Help:    "Database query duration in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
			},
			[]string{"operation"},
		),

		// Redis metrics
		redisConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_redis_connections_active",
			Help: "Number of active Redis connections",
		}),
		redisOperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "junoscommander_redis_operations_total",
				Help: "Total number of Redis operations",
			},
			[]string{"operation", "status"},
		),
		redisOperationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "junoscommander_redis_operation_duration_seconds",
				Help:    "Redis operation duration in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
			},
			[]string{"operation"},
		),

		// System metrics
		applicationInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "junoscommander_application_info",
				Help: "Application information",
			},
			[]string{"version", "build_date", "commit"},
		),
		uptime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "junoscommander_uptime_seconds",
			Help: "Application uptime in seconds",
		}),
		startTime: time.Now(),
		logger:    logger,
	}

	// Register all metrics
	prometheus.MustRegister(
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.httpRequestsInFlight,
		m.activeSSHConnections,
		m.sshConnectionsTotal,
		m.taskExecutionTotal,
		m.taskExecutionDuration,
		m.taskQueueSize,
		m.authAttemptsTotal,
		m.activeSessionsCount,
		m.dbConnectionsActive,
		m.dbConnectionsIdle,
		m.dbConnectionsTotal,
		m.dbQueriesTotal,
		m.dbQueryDuration,
		m.redisConnectionsActive,
		m.redisOperationsTotal,
		m.redisOperationDuration,
		m.applicationInfo,
		m.uptime,
	)

	// Set application info
	m.applicationInfo.WithLabelValues("dev", time.Now().Format("2006-01-02"), "unknown").Set(1)

	logger.Info("Prometheus metrics initialized")
	return m
}

// HTTPMiddleware returns a Gin middleware for collecting HTTP metrics
func (m *Metrics) HTTPMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		m.httpRequestsInFlight.Inc()

		// Process request
		c.Next()

		// Calculate duration and record metrics
		duration := time.Since(start)
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}

		m.httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration.Seconds())
		m.httpRequestsTotal.WithLabelValues(c.Request.Method, path, string(rune(c.Writer.Status()))).Inc()
		m.httpRequestsInFlight.Dec()
	})
}

// RecordSSHConnection records SSH connection metrics
func (m *Metrics) RecordSSHConnection(deviceType, status string) {
	m.sshConnectionsTotal.WithLabelValues(deviceType, status).Inc()
}

// SetActiveSSHConnections updates the active SSH connections gauge
func (m *Metrics) SetActiveSSHConnections(count float64) {
	m.activeSSHConnections.Set(count)
}

// RecordTaskExecution records task execution metrics
func (m *Metrics) RecordTaskExecution(taskType, status string, duration time.Duration) {
	m.taskExecutionTotal.WithLabelValues(taskType, status).Inc()
	m.taskExecutionDuration.WithLabelValues(taskType).Observe(duration.Seconds())
}

// SetTaskQueueSize updates the task queue size gauge
func (m *Metrics) SetTaskQueueSize(size float64) {
	m.taskQueueSize.Set(size)
}

// RecordAuthAttempt records authentication attempt metrics
func (m *Metrics) RecordAuthAttempt(method, result string) {
	m.authAttemptsTotal.WithLabelValues(method, result).Inc()
}

// SetActiveSessionsCount updates the active sessions count
func (m *Metrics) SetActiveSessionsCount(count float64) {
	m.activeSessionsCount.Set(count)
}

// UpdateDatabaseStats updates database connection metrics
func (m *Metrics) UpdateDatabaseStats(stats sql.DBStats) {
	m.dbConnectionsActive.Set(float64(stats.InUse))
	m.dbConnectionsIdle.Set(float64(stats.Idle))
	m.dbConnectionsTotal.Set(float64(stats.OpenConnections))
}

// RecordDatabaseQuery records database query metrics
func (m *Metrics) RecordDatabaseQuery(operation, status string, duration time.Duration) {
	m.dbQueriesTotal.WithLabelValues(operation, status).Inc()
	m.dbQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordRedisOperation records Redis operation metrics
func (m *Metrics) RecordRedisOperation(operation, status string, duration time.Duration) {
	m.redisOperationsTotal.WithLabelValues(operation, status).Inc()
	m.redisOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// SetRedisConnectionsActive updates Redis connections metric
func (m *Metrics) SetRedisConnectionsActive(count float64) {
	m.redisConnectionsActive.Set(count)
}

// UpdateUptime updates the uptime metric
func (m *Metrics) UpdateUptime() {
	m.uptime.Set(time.Since(m.startTime).Seconds())
}

// Handler returns the Prometheus metrics HTTP handler
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// DatabaseMetricsCollector implements a custom Prometheus collector for database metrics
type DatabaseMetricsCollector struct {
	db      *sql.DB
	metrics *Metrics
	logger  *zap.Logger
}

// NewDatabaseMetricsCollector creates a new database metrics collector
func NewDatabaseMetricsCollector(db *sql.DB, metrics *Metrics, logger *zap.Logger) *DatabaseMetricsCollector {
	return &DatabaseMetricsCollector{
		db:      db,
		metrics: metrics,
		logger:  logger,
	}
}

// StartMetricsCollection starts collecting metrics in the background
func (m *Metrics) StartMetricsCollection(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Stopping metrics collection")
			return
		case <-ticker.C:
			m.collectMetrics(db)
		}
	}
}

// collectMetrics collects various application metrics
func (m *Metrics) collectMetrics(db *sql.DB) {
	// Update uptime
	m.UpdateUptime()

	// Update database stats if available
	if db != nil {
		m.UpdateDatabaseStats(db.Stats())
	}

	// Log metrics collection
	m.logger.Debug("Metrics collected")
}

// MetricsWrapper provides a wrapper for instrumented operations
type MetricsWrapper struct {
	metrics *Metrics
}

// NewMetricsWrapper creates a new metrics wrapper
func NewMetricsWrapper(metrics *Metrics) *MetricsWrapper {
	return &MetricsWrapper{metrics: metrics}
}

// WrapDatabaseOperation wraps a database operation with metrics
func (mw *MetricsWrapper) WrapDatabaseOperation(operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	status := "success"
	if err != nil {
		status = "error"
	}

	mw.metrics.RecordDatabaseQuery(operation, status, duration)
	return err
}

// WrapRedisOperation wraps a Redis operation with metrics
func (mw *MetricsWrapper) WrapRedisOperation(operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	status := "success"
	if err != nil {
		status = "error"
	}

	mw.metrics.RecordRedisOperation(operation, status, duration)
	return err
}