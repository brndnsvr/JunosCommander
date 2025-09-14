package logger

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config holds logger configuration
type Config struct {
	Level       string `json:"level"`
	Format      string `json:"format"`      // json or console
	Output      string `json:"output"`      // stdout, stderr, or file path
	EnableCaller bool  `json:"enable_caller"`
	Environment string `json:"environment"` // development, staging, production
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	// RequestIDKey is the context key for request ID
	RequestIDKey contextKey = "request_id"
	// UserIDKey is the context key for user ID
	UserIDKey contextKey = "user_id"
	// SessionIDKey is the context key for session ID
	SessionIDKey contextKey = "session_id"
)

// NewLogger creates a new structured logger based on configuration
func NewLogger(config Config) (*zap.Logger, error) {
	// Parse log level
	level := zap.InfoLevel
	if config.Level != "" {
		if err := level.UnmarshalText([]byte(config.Level)); err != nil {
			return nil, err
		}
	}

	// Create encoder config
	var encoderConfig zapcore.EncoderConfig
	if config.Environment == "production" {
		encoderConfig = zap.NewProductionEncoderConfig()
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
	}

	// Customize encoder config
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "message"
	encoderConfig.CallerKey = "caller"
	encoderConfig.StacktraceKey = "stacktrace"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	// Create encoder based on format
	var encoder zapcore.Encoder
	if config.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create writer syncer based on output
	var writeSyncer zapcore.WriteSyncer
	switch config.Output {
	case "stdout", "":
		writeSyncer = zapcore.AddSync(os.Stdout)
	case "stderr":
		writeSyncer = zapcore.AddSync(os.Stderr)
	default:
		// File output
		if err := os.MkdirAll(filepath.Dir(config.Output), 0755); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(config.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.AddSync(file)
	}

	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// Create logger options
	var options []zap.Option
	if config.EnableCaller {
		options = append(options, zap.AddCaller(), zap.AddCallerSkip(1))
	}

	// Add stack trace for error level and above in production
	if config.Environment == "production" {
		options = append(options, zap.AddStacktrace(zapcore.ErrorLevel))
	} else {
		options = append(options, zap.AddStacktrace(zapcore.WarnLevel))
	}

	// Create logger
	logger := zap.New(core, options...)

	// Add initial fields
	logger = logger.With(
		zap.String("service", "junoscommander"),
		zap.String("version", "1.0.0"), // This could come from build info
		zap.String("environment", config.Environment),
	)

	return logger, nil
}

// NewDevelopmentLogger creates a logger optimized for development
func NewDevelopmentLogger() (*zap.Logger, error) {
	config := Config{
		Level:        "debug",
		Format:       "console",
		Output:       "stdout",
		EnableCaller: true,
		Environment:  "development",
	}
	return NewLogger(config)
}

// NewProductionLogger creates a logger optimized for production
func NewProductionLogger(outputPath string) (*zap.Logger, error) {
	config := Config{
		Level:        "info",
		Format:       "json",
		Output:       outputPath,
		EnableCaller: false,
		Environment:  "production",
	}
	return NewLogger(config)
}

// WithContext adds context fields to logger
func WithContext(logger *zap.Logger, ctx context.Context) *zap.Logger {
	fields := make([]zap.Field, 0)

	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok {
			fields = append(fields, zap.String("request_id", id))
		}
	}

	if userID := ctx.Value(UserIDKey); userID != nil {
		if id, ok := userID.(string); ok {
			fields = append(fields, zap.String("user_id", id))
		}
	}

	if sessionID := ctx.Value(SessionIDKey); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			fields = append(fields, zap.String("session_id", id))
		}
	}

	if len(fields) > 0 {
		return logger.With(fields...)
	}

	return logger
}

// SecurityLogger creates a logger specifically for security events
type SecurityLogger struct {
	logger *zap.Logger
}

// NewSecurityLogger creates a new security event logger
func NewSecurityLogger(baseLogger *zap.Logger) *SecurityLogger {
	return &SecurityLogger{
		logger: baseLogger.With(zap.String("category", "security")),
	}
}

// LogAuthAttempt logs an authentication attempt
func (sl *SecurityLogger) LogAuthAttempt(ctx context.Context, username, method, result, clientIP, userAgent string) {
	logger := WithContext(sl.logger, ctx)
	logger.Info("Authentication attempt",
		zap.String("username", username),
		zap.String("method", method),
		zap.String("result", result),
		zap.String("client_ip", clientIP),
		zap.String("user_agent", userAgent),
		zap.Time("timestamp", time.Now()),
	)
}

// LogPrivilegeEscalation logs privilege escalation events
func (sl *SecurityLogger) LogPrivilegeEscalation(ctx context.Context, username, fromRole, toRole, reason string) {
	logger := WithContext(sl.logger, ctx)
	logger.Warn("Privilege escalation",
		zap.String("username", username),
		zap.String("from_role", fromRole),
		zap.String("to_role", toRole),
		zap.String("reason", reason),
		zap.Time("timestamp", time.Now()),
	)
}

// LogSuspiciousActivity logs suspicious activities
func (sl *SecurityLogger) LogSuspiciousActivity(ctx context.Context, username, activity, clientIP string, details map[string]interface{}) {
	logger := WithContext(sl.logger, ctx)
	fields := []zap.Field{
		zap.String("username", username),
		zap.String("activity", activity),
		zap.String("client_ip", clientIP),
		zap.Time("timestamp", time.Now()),
	}

	for key, value := range details {
		fields = append(fields, zap.Any(key, value))
	}

	logger.Warn("Suspicious activity detected", fields...)
}

// AuditLogger creates a logger specifically for audit events
type AuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger creates a new audit event logger
func NewAuditLogger(baseLogger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: baseLogger.With(zap.String("category", "audit")),
	}
}

// LogResourceAccess logs resource access events
func (al *AuditLogger) LogResourceAccess(ctx context.Context, username, action, resourceType, resourceID string, success bool) {
	logger := WithContext(al.logger, ctx)
	logger.Info("Resource access",
		zap.String("username", username),
		zap.String("action", action),
		zap.String("resource_type", resourceType),
		zap.String("resource_id", resourceID),
		zap.Bool("success", success),
		zap.Time("timestamp", time.Now()),
	)
}

// LogConfigurationChange logs configuration changes
func (al *AuditLogger) LogConfigurationChange(ctx context.Context, username, component, changeType string, before, after interface{}) {
	logger := WithContext(al.logger, ctx)
	logger.Info("Configuration change",
		zap.String("username", username),
		zap.String("component", component),
		zap.String("change_type", changeType),
		zap.Any("before", before),
		zap.Any("after", after),
		zap.Time("timestamp", time.Now()),
	)
}

// LogDataExport logs data export events
func (al *AuditLogger) LogDataExport(ctx context.Context, username, dataType string, recordCount int, format string) {
	logger := WithContext(al.logger, ctx)
	logger.Info("Data export",
		zap.String("username", username),
		zap.String("data_type", dataType),
		zap.Int("record_count", recordCount),
		zap.String("format", format),
		zap.Time("timestamp", time.Now()),
	)
}

// PerformanceLogger creates a logger for performance monitoring
type PerformanceLogger struct {
	logger *zap.Logger
}

// NewPerformanceLogger creates a new performance logger
func NewPerformanceLogger(baseLogger *zap.Logger) *PerformanceLogger {
	return &PerformanceLogger{
		logger: baseLogger.With(zap.String("category", "performance")),
	}
}

// LogSlowQuery logs slow database queries
func (pl *PerformanceLogger) LogSlowQuery(ctx context.Context, query string, duration time.Duration, threshold time.Duration) {
	if duration > threshold {
		logger := WithContext(pl.logger, ctx)
		logger.Warn("Slow query detected",
			zap.String("query", query),
			zap.Duration("duration", duration),
			zap.Duration("threshold", threshold),
			zap.Time("timestamp", time.Now()),
		)
	}
}

// LogHighResourceUsage logs high resource usage
func (pl *PerformanceLogger) LogHighResourceUsage(ctx context.Context, resourceType string, usage float64, threshold float64, unit string) {
	if usage > threshold {
		logger := WithContext(pl.logger, ctx)
		logger.Warn("High resource usage",
			zap.String("resource_type", resourceType),
			zap.Float64("usage", usage),
			zap.Float64("threshold", threshold),
			zap.String("unit", unit),
			zap.Time("timestamp", time.Now()),
		)
	}
}

// HTTPLogger creates structured logs for HTTP requests
type HTTPLogger struct {
	logger *zap.Logger
}

// NewHTTPLogger creates a new HTTP logger
func NewHTTPLogger(baseLogger *zap.Logger) *HTTPLogger {
	return &HTTPLogger{
		logger: baseLogger.With(zap.String("category", "http")),
	}
}

// LogRequest logs HTTP request details
func (hl *HTTPLogger) LogRequest(ctx context.Context, method, path, userAgent, clientIP string, statusCode int, duration time.Duration, size int64) {
	logger := WithContext(hl.logger, ctx)

	level := zapcore.InfoLevel
	if statusCode >= 400 {
		if statusCode >= 500 {
			level = zapcore.ErrorLevel
		} else {
			level = zapcore.WarnLevel
		}
	}

	logger.Log(level, "HTTP request",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("user_agent", userAgent),
		zap.String("client_ip", clientIP),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", duration),
		zap.Int64("response_size", size),
		zap.Time("timestamp", time.Now()),
	)
}

// SanitizeForLogging sanitizes sensitive data for logging
func SanitizeForLogging(input string) string {
	// Remove or mask sensitive patterns
	sensitive := []string{"password", "token", "secret", "key", "auth"}

	for _, keyword := range sensitive {
		if strings.Contains(strings.ToLower(input), keyword) {
			return "[REDACTED]"
		}
	}

	return input
}

// LogRotation manages log file rotation (basic implementation)
type LogRotation struct {
	maxSize    int64 // Maximum size in bytes
	maxAge     time.Duration
	maxBackups int
	filePath   string
}

// NewLogRotation creates a new log rotation manager
func NewLogRotation(filePath string, maxSize int64, maxAge time.Duration, maxBackups int) *LogRotation {
	return &LogRotation{
		maxSize:    maxSize,
		maxAge:     maxAge,
		maxBackups: maxBackups,
		filePath:   filePath,
	}
}

// ShouldRotate checks if log file should be rotated
func (lr *LogRotation) ShouldRotate() bool {
	info, err := os.Stat(lr.filePath)
	if err != nil {
		return false
	}

	// Check size
	if info.Size() >= lr.maxSize {
		return true
	}

	// Check age
	if time.Since(info.ModTime()) >= lr.maxAge {
		return true
	}

	return false
}

// Rotate performs log file rotation
func (lr *LogRotation) Rotate() error {
	if !lr.ShouldRotate() {
		return nil
	}

	// Create backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	backupPath := lr.filePath + "." + timestamp

	// Rename current log file
	if err := os.Rename(lr.filePath, backupPath); err != nil {
		return err
	}

	// Clean up old backups
	return lr.cleanupOldBackups()
}

// cleanupOldBackups removes old backup files
func (lr *LogRotation) cleanupOldBackups() error {
	dir := filepath.Dir(lr.filePath)
	baseName := filepath.Base(lr.filePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var backups []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), baseName+".") {
			backups = append(backups, filepath.Join(dir, entry.Name()))
		}
	}

	// Keep only the most recent backups
	if len(backups) > lr.maxBackups {
		for i := 0; i < len(backups)-lr.maxBackups; i++ {
			os.Remove(backups[i])
		}
	}

	return nil
}