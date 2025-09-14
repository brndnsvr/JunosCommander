// Comprehensive Error Handling and Circuit Breaker Implementation
// Provides robust error handling, retry logic, and failure isolation for network operations

package errorhandling

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrorHandler provides centralized error handling with classification and recovery
type ErrorHandler struct {
	config          ErrorConfig
	circuitBreakers map[string]*CircuitBreaker
	retryPolicies   map[string]*RetryPolicy
	errorClassifier *ErrorClassifier
	metrics         *ErrorMetrics
	logger          Logger
	mu              sync.RWMutex
}

// CircuitBreaker implements the circuit breaker pattern for failure isolation
type CircuitBreaker struct {
	name            string
	config          CircuitBreakerConfig
	state           CircuitState
	failureCount    int64
	successCount    int64
	lastFailureTime time.Time
	lastStateChange time.Time
	halfOpenCount   int32
	mu              sync.RWMutex
	metrics         *CircuitBreakerMetrics
	logger          Logger
}

// RetryPolicy defines retry behavior with exponential backoff and jitter
type RetryPolicy struct {
	MaxAttempts       int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
	JitterEnabled     bool
	RetryableErrors   []ErrorType
	CircuitBreaker    string
}

// ErrorClassifier categorizes errors and determines appropriate handling
type ErrorClassifier struct {
	patterns map[ErrorType][]ErrorPattern
	mu       sync.RWMutex
}

// NetworkError represents a network-related error with context
type NetworkError struct {
	Type        ErrorType
	Category    ErrorCategory
	Device      string
	Command     string
	Original    error
	Retryable   bool
	Temporary   bool
	Timeout     bool
	Code        string
	Message     string
	Timestamp   time.Time
	Context     map[string]interface{}
	Stack       string
}

// ErrorConfig holds error handling configuration
type ErrorConfig struct {
	// Circuit breaker settings
	CircuitBreakerEnabled     bool
	DefaultFailureThreshold   int
	DefaultRecoveryTimeout    time.Duration
	DefaultHalfOpenMaxReqs    int

	// Retry settings
	DefaultMaxRetries         int
	DefaultInitialDelay       time.Duration
	DefaultMaxDelay           time.Duration
	DefaultBackoffMultiplier  float64
	JitterEnabled             bool

	// Timeout settings
	HealthCheckTimeout        time.Duration
	ConnectionTimeout         time.Duration
	CommandTimeout            time.Duration
	AuthenticationTimeout     time.Duration

	// Error classification
	EnableErrorClassification bool
	CustomErrorPatterns       map[ErrorType][]ErrorPattern

	// Metrics and monitoring
	ErrorMetricsEnabled       bool
	ErrorMetricsRetention     time.Duration
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	FailureThreshold   int
	RecoveryTimeout    time.Duration
	HalfOpenMaxReqs    int
	MinRequestCount    int
	SuccessThreshold   int
}

// ErrorType categorizes different types of errors
type ErrorType string

const (
	// Connection errors
	ErrorTypeConnectionRefused   ErrorType = "connection_refused"
	ErrorTypeConnectionTimeout   ErrorType = "connection_timeout"
	ErrorTypeConnectionReset     ErrorType = "connection_reset"
	ErrorTypeConnectionLost      ErrorType = "connection_lost"

	// Authentication errors
	ErrorTypeAuthenticationFailed ErrorType = "authentication_failed"
	ErrorTypePermissionDenied     ErrorType = "permission_denied"
	ErrorTypeAccountLocked        ErrorType = "account_locked"
	ErrorTypePasswordExpired      ErrorType = "password_expired"

	// SSH protocol errors
	ErrorTypeSSHHandshakeFailed   ErrorType = "ssh_handshake_failed"
	ErrorTypeSSHHostKeyMismatch   ErrorType = "ssh_host_key_mismatch"
	ErrorTypeSSHProtocolError     ErrorType = "ssh_protocol_error"
	ErrorTypeSSHSessionFailed     ErrorType = "ssh_session_failed"

	// Command execution errors
	ErrorTypeCommandTimeout       ErrorType = "command_timeout"
	ErrorTypeCommandSyntaxError   ErrorType = "command_syntax_error"
	ErrorTypeCommandNotFound      ErrorType = "command_not_found"
	ErrorTypePrivilegeRequired    ErrorType = "privilege_required"

	// Device-specific errors
	ErrorTypeDeviceNotResponding  ErrorType = "device_not_responding"
	ErrorTypeDeviceConfigLocked   ErrorType = "device_config_locked"
	ErrorTypeDeviceResourceLimit  ErrorType = "device_resource_limit"
	ErrorTypeDeviceUnsupported    ErrorType = "device_unsupported"

	// Junos-specific errors
	ErrorTypeJunosCommitFailed    ErrorType = "junos_commit_failed"
	ErrorTypeJunosRollbackFailed  ErrorType = "junos_rollback_failed"
	ErrorTypeJunosConfigError     ErrorType = "junos_config_error"
	ErrorTypeJunosValidationError ErrorType = "junos_validation_error"

	// System errors
	ErrorTypeResourceExhausted    ErrorType = "resource_exhausted"
	ErrorTypeMemoryError          ErrorType = "memory_error"
	ErrorTypeIOError              ErrorType = "io_error"
	ErrorTypeInternalError        ErrorType = "internal_error"
)

// ErrorCategory groups related error types
type ErrorCategory string

const (
	CategoryConnection    ErrorCategory = "connection"
	CategoryAuthentication ErrorCategory = "authentication"
	CategoryCommand       ErrorCategory = "command"
	CategoryDevice        ErrorCategory = "device"
	CategorySystem        ErrorCategory = "system"
)

// CircuitState represents the current state of a circuit breaker
type CircuitState int32

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// ErrorPattern defines patterns for error classification
type ErrorPattern struct {
	Pattern     string
	IsRegex     bool
	Retryable   bool
	Temporary   bool
	Category    ErrorCategory
	Severity    ErrorSeverity
}

// ErrorSeverity indicates the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ErrorMetrics tracks error statistics
type ErrorMetrics struct {
	TotalErrors         int64
	ErrorsByType        map[ErrorType]int64
	ErrorsByCategory    map[ErrorCategory]int64
	RetriableErrors     int64
	NonRetriableErrors  int64
	RetriesAttempted    int64
	RetriesSuccessful   int64
	CircuitBreakerTrips int64
	LastError           *NetworkError
	mu                  sync.RWMutex
}

// CircuitBreakerMetrics tracks circuit breaker statistics
type CircuitBreakerMetrics struct {
	Name                string
	State               CircuitState
	FailureCount        int64
	SuccessCount        int64
	TotalRequests       int64
	SuccessRate         float64
	FailureRate         float64
	StateChanges        int64
	LastStateChange     time.Time
	TimeInState         time.Duration
	AvgResponseTime     time.Duration
}

// NewErrorHandler creates a new error handler with comprehensive configuration
func NewErrorHandler(config ErrorConfig, logger Logger) *ErrorHandler {
	handler := &ErrorHandler{
		config:          config,
		circuitBreakers: make(map[string]*CircuitBreaker),
		retryPolicies:   make(map[string]*RetryPolicy),
		errorClassifier: NewErrorClassifier(config.CustomErrorPatterns),
		metrics:         &ErrorMetrics{
			ErrorsByType:     make(map[ErrorType]int64),
			ErrorsByCategory: make(map[ErrorCategory]int64),
		},
		logger: logger,
	}

	// Initialize default retry policies
	handler.initializeDefaultRetryPolicies()

	return handler
}

// HandleError processes an error with classification and recovery logic
func (h *ErrorHandler) HandleError(ctx context.Context, err error, operation string, deviceID string) *ErrorHandlingResult {
	if err == nil {
		return &ErrorHandlingResult{Success: true}
	}

	// Classify the error
	networkErr := h.classifyError(err, operation, deviceID)

	// Record error metrics
	h.recordError(networkErr)

	// Check circuit breaker
	circuitBreakerName := fmt.Sprintf("device_%s", deviceID)
	if h.config.CircuitBreakerEnabled {
		if cb := h.getCircuitBreaker(circuitBreakerName); cb != nil {
			if !cb.AllowRequest() {
				h.logger.Warn("Circuit breaker open, rejecting request",
					"device", deviceID,
					"operation", operation,
					"circuit_breaker", circuitBreakerName,
				)
				return &ErrorHandlingResult{
					Success:        false,
					Error:          networkErr,
					CircuitOpen:    true,
					ShouldRetry:    false,
				}
			}
		}
	}

	// Determine retry policy
	retryPolicy := h.getRetryPolicy(operation, networkErr.Type)

	// Create error handling result
	result := &ErrorHandlingResult{
		Success:       false,
		Error:         networkErr,
		ShouldRetry:   networkErr.Retryable && retryPolicy != nil,
		RetryPolicy:   retryPolicy,
		CircuitOpen:   false,
		NextRetryDelay: 0,
	}

	// Calculate next retry delay if retryable
	if result.ShouldRetry && retryPolicy != nil {
		result.NextRetryDelay = h.calculateRetryDelay(retryPolicy, 0)
	}

	return result
}

// ExecuteWithRetry executes an operation with retry logic and circuit breaker protection
func (h *ErrorHandler) ExecuteWithRetry(ctx context.Context, operation func(context.Context) error, operationName string, deviceID string) error {
	circuitBreakerName := fmt.Sprintf("device_%s", deviceID)
	retryPolicy := h.getRetryPolicy(operationName, "")

	var lastError error
	maxAttempts := 1
	if retryPolicy != nil {
		maxAttempts = retryPolicy.MaxAttempts
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check context cancellation
		if err := ctx.Err(); err != nil {
			return err
		}

		// Check circuit breaker
		if h.config.CircuitBreakerEnabled {
			if cb := h.getCircuitBreaker(circuitBreakerName); cb != nil {
				if !cb.AllowRequest() {
					return fmt.Errorf("circuit breaker open for device %s", deviceID)
				}
			}
		}

		// Execute operation
		startTime := time.Now()
		err := operation(ctx)
		duration := time.Since(startTime)

		if err == nil {
			// Success - record in circuit breaker
			if h.config.CircuitBreakerEnabled {
				if cb := h.getCircuitBreaker(circuitBreakerName); cb != nil {
					cb.RecordSuccess(duration)
				}
			}
			return nil
		}

		lastError = err

		// Handle error
		result := h.HandleError(ctx, err, operationName, deviceID)

		// Record failure in circuit breaker
		if h.config.CircuitBreakerEnabled {
			if cb := h.getCircuitBreaker(circuitBreakerName); cb != nil {
				cb.RecordFailure()
			}
		}

		// Check if we should retry
		if !result.ShouldRetry || attempt == maxAttempts-1 {
			break
		}

		// Calculate retry delay
		delay := h.calculateRetryDelay(retryPolicy, attempt)

		h.logger.Debug("Retrying operation after failure",
			"operation", operationName,
			"device", deviceID,
			"attempt", attempt+1,
			"max_attempts", maxAttempts,
			"delay", delay,
			"error", err.Error(),
		)

		// Wait for retry delay with context cancellation
		select {
		case <-time.After(delay):
			// Continue to retry
		case <-ctx.Done():
			return ctx.Err()
		}

		atomic.AddInt64(&h.metrics.RetriesAttempted, 1)
	}

	return lastError
}

// classifyError analyzes an error and returns a classified NetworkError
func (h *ErrorHandler) classifyError(err error, operation string, deviceID string) *NetworkError {
	networkErr := &NetworkError{
		Original:  err,
		Device:    deviceID,
		Command:   operation,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}

	// Classify based on error type and message
	errorMsg := err.Error()

	// SSH-specific error handling
	if sshErr, ok := err.(*ssh.ExitError); ok {
		networkErr.Code = fmt.Sprintf("ssh_exit_%d", sshErr.ExitStatus())
		networkErr.Type = ErrorTypeCommandSyntaxError
		networkErr.Category = CategoryCommand
		networkErr.Retryable = false
	} else if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			networkErr.Type = ErrorTypeConnectionTimeout
			networkErr.Timeout = true
			networkErr.Temporary = netErr.Temporary()
		} else if netErr.Temporary() {
			networkErr.Type = ErrorTypeConnectionLost
			networkErr.Temporary = true
		}
		networkErr.Category = CategoryConnection
		networkErr.Retryable = netErr.Temporary()
	} else {
		// Pattern-based classification
		networkErr = h.classifyByPattern(networkErr, errorMsg)
	}

	// Junos-specific error classification
	if strings.Contains(strings.ToLower(errorMsg), "junos") {
		networkErr = h.classifyJunosError(networkErr, errorMsg)
	}

	// Set default values if not classified
	if networkErr.Type == "" {
		networkErr.Type = ErrorTypeInternalError
		networkErr.Category = CategorySystem
		networkErr.Retryable = false
	}

	networkErr.Message = errorMsg

	return networkErr
}

// classifyByPattern uses pattern matching to classify errors
func (h *ErrorHandler) classifyByPattern(networkErr *NetworkError, errorMsg string) *NetworkError {
	patterns := map[ErrorType][]string{
		ErrorTypeConnectionRefused: {
			"connection refused",
			"connect: connection refused",
		},
		ErrorTypeConnectionTimeout: {
			"connection timeout",
			"i/o timeout",
			"dial timeout",
		},
		ErrorTypeAuthenticationFailed: {
			"authentication failed",
			"invalid username or password",
			"access denied",
			"login failed",
		},
		ErrorTypePermissionDenied: {
			"permission denied",
			"access denied",
			"insufficient privileges",
		},
		ErrorTypeCommandNotFound: {
			"command not found",
			"invalid command",
			"unknown command",
		},
		ErrorTypeCommandSyntaxError: {
			"syntax error",
			"invalid syntax",
			"parse error",
		},
		ErrorTypeDeviceNotResponding: {
			"device not responding",
			"no response",
			"timed out waiting",
		},
	}

	lowerMsg := strings.ToLower(errorMsg)

	for errorType, patternList := range patterns {
		for _, pattern := range patternList {
			if strings.Contains(lowerMsg, pattern) {
				networkErr.Type = errorType
				networkErr.Category = h.getErrorCategory(errorType)
				networkErr.Retryable = h.isRetryableError(errorType)
				return networkErr
			}
		}
	}

	return networkErr
}

// classifyJunosError provides Junos-specific error classification
func (h *ErrorHandler) classifyJunosError(networkErr *NetworkError, errorMsg string) *NetworkError {
	lowerMsg := strings.ToLower(errorMsg)

	junosPatterns := map[ErrorType][]string{
		ErrorTypeJunosCommitFailed: {
			"commit failed",
			"commit complete with errors",
			"commit check failed",
		},
		ErrorTypeJunosRollbackFailed: {
			"rollback failed",
			"rollback 0 failed",
		},
		ErrorTypeJunosConfigError: {
			"configuration error",
			"config error",
			"missing mandatory statement",
		},
		ErrorTypeJunosValidationError: {
			"validation error",
			"schema validation failed",
			"constraint check failed",
		},
		ErrorTypeDeviceConfigLocked: {
			"configuration database locked",
			"another user is editing",
			"database locked",
		},
	}

	for errorType, patterns := range junosPatterns {
		for _, pattern := range patterns {
			if strings.Contains(lowerMsg, pattern) {
				networkErr.Type = errorType
				networkErr.Category = CategoryDevice
				networkErr.Retryable = h.isJunosErrorRetryable(errorType)
				return networkErr
			}
		}
	}

	return networkErr
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(name string, config CircuitBreakerConfig, logger Logger) *CircuitBreaker {
	return &CircuitBreaker{
		name:            name,
		config:          config,
		state:           StateClosed,
		lastStateChange: time.Now(),
		metrics: &CircuitBreakerMetrics{
			Name:            name,
			State:           StateClosed,
			LastStateChange: time.Now(),
		},
		logger: logger,
	}
}

// AllowRequest determines if a request should be allowed through the circuit breaker
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if recovery timeout has passed
		if now.Sub(cb.lastFailureTime) >= cb.config.RecoveryTimeout {
			cb.setState(StateHalfOpen)
			cb.logger.Info("Circuit breaker transitioning to half-open",
				"name", cb.name,
				"failure_count", cb.failureCount,
			)
			return true
		}
		return false

	case StateHalfOpen:
		// Allow limited requests in half-open state
		if atomic.LoadInt32(&cb.halfOpenCount) < int32(cb.config.HalfOpenMaxReqs) {
			atomic.AddInt32(&cb.halfOpenCount, 1)
			return true
		}
		return false

	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess(duration time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.AddInt64(&cb.successCount, 1)
	cb.metrics.TotalRequests++
	cb.updateMetrics()

	if cb.state == StateHalfOpen {
		// Reset failure count on success in half-open state
		if cb.successCount >= int64(cb.config.SuccessThreshold) {
			cb.setState(StateClosed)
			cb.logger.Info("Circuit breaker closed after successful recovery",
				"name", cb.name,
				"success_count", cb.successCount,
			)
		}
	}

	// Reset half-open counter
	atomic.StoreInt32(&cb.halfOpenCount, 0)
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.AddInt64(&cb.failureCount, 1)
	cb.lastFailureTime = time.Now()
	cb.metrics.TotalRequests++
	cb.updateMetrics()

	if cb.state == StateClosed {
		// Check if we should open the circuit
		if cb.failureCount >= int64(cb.config.FailureThreshold) {
			cb.setState(StateOpen)
			cb.logger.Warn("Circuit breaker opened due to failures",
				"name", cb.name,
				"failure_count", cb.failureCount,
				"threshold", cb.config.FailureThreshold,
			)
		}
	} else if cb.state == StateHalfOpen {
		// Return to open state on failure during half-open
		cb.setState(StateOpen)
		cb.logger.Warn("Circuit breaker returned to open state after half-open failure",
			"name", cb.name,
		)
	}

	// Reset half-open counter
	atomic.StoreInt32(&cb.halfOpenCount, 0)
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(newState CircuitState) {
	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = time.Now()
	cb.metrics.State = newState
	cb.metrics.StateChanges++
	cb.metrics.LastStateChange = cb.lastStateChange

	// Reset counters on state change
	if newState == StateClosed {
		cb.failureCount = 0
		cb.successCount = 0
	}
}

// updateMetrics updates circuit breaker metrics
func (cb *CircuitBreaker) updateMetrics() {
	total := cb.metrics.TotalRequests
	if total > 0 {
		cb.metrics.SuccessRate = float64(cb.successCount) / float64(total) * 100
		cb.metrics.FailureRate = float64(cb.failureCount) / float64(total) * 100
	}
	cb.metrics.TimeInState = time.Since(cb.lastStateChange)
}

// calculateRetryDelay calculates the delay before the next retry attempt
func (h *ErrorHandler) calculateRetryDelay(policy *RetryPolicy, attempt int) time.Duration {
	if policy == nil {
		return h.config.DefaultInitialDelay
	}

	// Calculate exponential backoff
	delay := policy.InitialDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * policy.BackoffMultiplier)
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
			break
		}
	}

	// Add jitter if enabled
	if policy.JitterEnabled {
		jitter := time.Duration(rand.Float64() * float64(delay) * 0.1) // 10% jitter
		delay += jitter
	}

	return delay
}

// Helper methods and additional functionality...

// ErrorHandlingResult contains the result of error handling
type ErrorHandlingResult struct {
	Success        bool
	Error          *NetworkError
	ShouldRetry    bool
	RetryPolicy    *RetryPolicy
	CircuitOpen    bool
	NextRetryDelay time.Duration
}

// Additional helper methods would be implemented here...
func (h *ErrorHandler) getCircuitBreaker(name string) *CircuitBreaker { return nil }
func (h *ErrorHandler) getRetryPolicy(operation string, errorType ErrorType) *RetryPolicy { return nil }
func (h *ErrorHandler) recordError(err *NetworkError) {}
func (h *ErrorHandler) getErrorCategory(errorType ErrorType) ErrorCategory { return CategorySystem }
func (h *ErrorHandler) isRetryableError(errorType ErrorType) bool { return false }
func (h *ErrorHandler) isJunosErrorRetryable(errorType ErrorType) bool { return false }
func (h *ErrorHandler) initializeDefaultRetryPolicies() {}

func NewErrorClassifier(patterns map[ErrorType][]ErrorPattern) *ErrorClassifier {
	return &ErrorClassifier{patterns: make(map[ErrorType][]ErrorPattern)}
}