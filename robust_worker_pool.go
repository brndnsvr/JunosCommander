// Robust Worker Pool for Production Network Task Execution
// Supports context cancellation, backpressure handling, and graceful degradation

package worker

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// WorkerPool manages task execution with intelligent load balancing
type WorkerPool struct {
	// Core configuration
	config         WorkerConfig

	// Task management
	taskQueue      chan Task
	priorityQueue  *PriorityQueue
	resultHandler  ResultHandler

	// Worker management
	workers        []*Worker
	workerCount    int32
	activeWorkers  int32
	shutdownChan   chan struct{}
	wg             sync.WaitGroup

	// Backpressure and load shedding
	loadShedder    *LoadShedder
	backpressure   *BackpressureController

	// Metrics and monitoring
	metrics        *WorkerMetrics
	healthMonitor  *HealthMonitor
	logger         Logger

	// Circuit breaker for failing devices
	circuitBreakers map[string]*CircuitBreaker
	cbMutex         sync.RWMutex

	// Context cancellation
	ctx            context.Context
	cancel         context.CancelFunc

	// Dynamic scaling
	scaler         *DynamicScaler
	scalingEnabled bool
}

// Worker represents an individual task execution worker
type Worker struct {
	id           int
	pool         *WorkerPool
	taskChan     chan Task
	stopChan     chan struct{}
	isActive     bool
	lastActivity time.Time
	tasksHandled int64
	mu           sync.RWMutex
}

// Task represents a unit of work to be executed
type Task struct {
	ID              string
	Type            TaskType
	Priority        Priority
	DeviceIDs       []int
	Commands        []string
	Parameters      map[string]interface{}
	Timeout         time.Duration
	RetryPolicy     RetryPolicy
	Context         context.Context
	Cancel          context.CancelFunc
	SubmittedAt     time.Time
	DeadlineAt      time.Time
	UserID          string
	SessionID       string
	Tags            []string
	Dependencies    []string
	Callback        TaskCallback
}

// TaskResult contains the result of task execution
type TaskResult struct {
	TaskID          string
	Status          TaskStatus
	Results         []DeviceResult
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Error           error
	Metadata        map[string]interface{}
	RetryCount      int
	WorkerID        int
}

// DeviceResult contains results from a specific device
type DeviceResult struct {
	DeviceID     int
	Hostname     string
	Commands     []CommandResult
	Status       DeviceStatus
	Error        error
	Duration     time.Duration
	ConnectionID string
}

// CommandResult contains the result of a single command
type CommandResult struct {
	Command   string
	Output    string
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

// WorkerConfig holds worker pool configuration
type WorkerConfig struct {
	// Basic configuration
	WorkerCount          int
	QueueSize            int
	MaxConcurrentTasks   int
	TaskTimeout          time.Duration

	// Scaling configuration
	MinWorkers           int
	MaxWorkers           int
	ScaleUpThreshold     float64
	ScaleDownThreshold   float64
	ScaleUpCooldown      time.Duration
	ScaleDownCooldown    time.Duration

	// Backpressure configuration
	BackpressureEnabled  bool
	MaxQueueUtilization  float64
	LoadSheddingEnabled  bool
	MaxMemoryUsage       int64

	// Retry configuration
	DefaultRetryAttempts int
	RetryBackoffMin      time.Duration
	RetryBackoffMax      time.Duration
	RetryBackoffFactor   float64

	// Circuit breaker configuration
	CircuitBreakerEnabled     bool
	CircuitBreakerThreshold   int
	CircuitBreakerTimeout     time.Duration
	CircuitBreakerMaxRequests int

	// Monitoring configuration
	MetricsEnabled       bool
	HealthCheckInterval  time.Duration
	SlowTaskThreshold    time.Duration
}

// WorkerMetrics tracks worker pool performance
type WorkerMetrics struct {
	// Task metrics
	TasksSubmitted       int64
	TasksCompleted       int64
	TasksFailed          int64
	TasksCancelled       int64
	TasksRetried         int64
	TasksShedded         int64

	// Queue metrics
	QueueDepth           int64
	MaxQueueDepth        int64
	QueueUtilization     float64

	// Worker metrics
	ActiveWorkers        int32
	IdleWorkers          int32
	BusyWorkers          int32

	// Performance metrics
	AverageTaskDuration  time.Duration
	P95TaskDuration      time.Duration
	P99TaskDuration      time.Duration
	TaskThroughput       float64

	// Resource metrics
	MemoryUsage          int64
	CPUUsage             float64
	GoroutineCount       int64

	// Error metrics
	ErrorRate            float64
	CircuitBreakerTrips  int64
	LastError            error
	LastErrorTime        time.Time
}

// TaskType defines the type of task to execute
type TaskType string

const (
	TaskTypeCommand       TaskType = "command"
	TaskTypeConfig        TaskType = "config"
	TaskTypeBackup        TaskType = "backup"
	TaskTypeHealthCheck   TaskType = "health_check"
	TaskTypeDiscovery     TaskType = "discovery"
	TaskTypeBulkOperation TaskType = "bulk_operation"
)

// Priority defines task execution priority
type Priority int

const (
	PriorityLow Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// TaskStatus represents the current status of a task
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
	TaskStatusRetrying   TaskStatus = "retrying"
)

// DeviceStatus represents the status of operation on a device
type DeviceStatus string

const (
	DeviceStatusSuccess    DeviceStatus = "success"
	DeviceStatusFailed     DeviceStatus = "failed"
	DeviceStatusTimeout    DeviceStatus = "timeout"
	DeviceStatusCancelled  DeviceStatus = "cancelled"
	DeviceStatusSkipped    DeviceStatus = "skipped"
)

// NewWorkerPool creates a new worker pool with advanced features
func NewWorkerPool(config WorkerConfig, logger Logger) (*WorkerPool, error) {
	if config.WorkerCount <= 0 {
		config.WorkerCount = runtime.NumCPU()
	}

	if config.MinWorkers <= 0 {
		config.MinWorkers = 1
	}

	if config.MaxWorkers <= 0 {
		config.MaxWorkers = config.WorkerCount * 2
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		config:          config,
		taskQueue:       make(chan Task, config.QueueSize),
		priorityQueue:   NewPriorityQueue(),
		workers:         make([]*Worker, 0, config.MaxWorkers),
		shutdownChan:    make(chan struct{}),
		circuitBreakers: make(map[string]*CircuitBreaker),
		metrics:         &WorkerMetrics{},
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
		scalingEnabled:  config.MinWorkers != config.MaxWorkers,
	}

	// Initialize components
	pool.loadShedder = NewLoadShedder(config, pool.metrics, logger)
	pool.backpressure = NewBackpressureController(config, pool.metrics, logger)
	pool.healthMonitor = NewHealthMonitor(config.HealthCheckInterval, logger)

	if pool.scalingEnabled {
		pool.scaler = NewDynamicScaler(config, pool, logger)
	}

	// Start initial workers
	if err := pool.scaleWorkers(config.WorkerCount); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start initial workers: %w", err)
	}

	// Start background routines
	pool.startBackgroundRoutines()

	logger.Info("Worker pool initialized",
		"workers", config.WorkerCount,
		"queue_size", config.QueueSize,
		"scaling_enabled", pool.scalingEnabled,
	)

	return pool, nil
}

// Submit submits a task for execution with backpressure handling
func (p *WorkerPool) Submit(task Task) error {
	// Validate task
	if err := p.validateTask(&task); err != nil {
		return fmt.Errorf("task validation failed: %w", err)
	}

	// Check load shedding
	if p.config.LoadSheddingEnabled && p.loadShedder.ShouldShed() {
		atomic.AddInt64(&p.metrics.TasksShedded, 1)
		return errors.New("task rejected due to load shedding")
	}

	// Apply backpressure
	if p.config.BackpressureEnabled {
		if !p.backpressure.AllowSubmission() {
			return errors.New("task rejected due to backpressure")
		}
	}

	// Set task metadata
	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	task.SubmittedAt = time.Now()
	if task.DeadlineAt.IsZero() && task.Timeout > 0 {
		task.DeadlineAt = time.Now().Add(task.Timeout)
	}

	// Create task context with cancellation
	if task.Context == nil {
		task.Context, task.Cancel = context.WithTimeout(p.ctx, task.Timeout)
	}

	// Submit task based on priority
	if task.Priority >= PriorityHigh {
		// High priority tasks go to priority queue
		p.priorityQueue.Push(task)
	} else {
		// Normal priority tasks go to regular queue
		select {
		case p.taskQueue <- task:
			// Task submitted successfully
		case <-p.ctx.Done():
			return errors.New("worker pool is shutting down")
		default:
			// Queue is full, check if we can expand
			if p.scalingEnabled && p.canScaleUp() {
				p.scaler.RequestScaleUp()
				// Try again after requesting scale up
				select {
				case p.taskQueue <- task:
					// Task submitted successfully after scale up
				default:
					return errors.New("task queue is full and cannot scale up")
				}
			} else {
				return errors.New("task queue is full")
			}
		}
	}

	atomic.AddInt64(&p.metrics.TasksSubmitted, 1)
	atomic.AddInt64(&p.metrics.QueueDepth, 1)

	p.logger.Debug("Task submitted",
		"task_id", task.ID,
		"type", task.Type,
		"priority", task.Priority,
		"device_count", len(task.DeviceIDs),
	)

	return nil
}

// SubmitBatch submits multiple tasks as a batch with dependency handling
func (p *WorkerPool) SubmitBatch(tasks []Task, dependencies []string) error {
	if len(tasks) == 0 {
		return errors.New("empty task batch")
	}

	// Set dependencies for all tasks
	for i := range tasks {
		tasks[i].Dependencies = dependencies
	}

	// Submit all tasks
	for _, task := range tasks {
		if err := p.Submit(task); err != nil {
			return fmt.Errorf("failed to submit batch task %s: %w", task.ID, err)
		}
	}

	return nil
}

// worker is the main worker loop
func (p *WorkerPool) worker(id int) {
	defer p.wg.Done()

	worker := &Worker{
		id:       id,
		pool:     p,
		taskChan: make(chan Task, 1),
		stopChan: make(chan struct{}),
	}

	p.logger.Debug("Worker started", "worker_id", id)

	for {
		select {
		case <-worker.stopChan:
			p.logger.Debug("Worker stopping", "worker_id", id)
			return

		case <-p.shutdownChan:
			p.logger.Debug("Worker shutting down", "worker_id", id)
			return

		default:
			// Try to get task from priority queue first
			task, ok := p.priorityQueue.Pop()
			if !ok {
				// No priority task, try regular queue
				select {
				case task = <-p.taskQueue:
					// Got regular task
				case <-time.After(100 * time.Millisecond):
					// No task available, continue loop
					continue
				}
			}

			// Update worker status
			worker.mu.Lock()
			worker.isActive = true
			worker.lastActivity = time.Now()
			worker.mu.Unlock()

			atomic.AddInt32(&p.activeWorkers, 1)
			atomic.AddInt64(&p.metrics.QueueDepth, -1)

			// Execute task
			p.executeTask(worker, task)

			// Update worker status
			worker.mu.Lock()
			worker.isActive = false
			worker.tasksHandled++
			worker.mu.Unlock()

			atomic.AddInt32(&p.activeWorkers, -1)
		}
	}
}

// executeTask executes a single task with comprehensive error handling
func (p *WorkerPool) executeTask(worker *Worker, task Task) {
	startTime := time.Now()

	p.logger.Debug("Executing task",
		"task_id", task.ID,
		"worker_id", worker.id,
		"type", task.Type,
	)

	// Create task result
	result := &TaskResult{
		TaskID:    task.ID,
		Status:    TaskStatusRunning,
		StartTime: startTime,
		WorkerID:  worker.id,
		Results:   make([]DeviceResult, 0, len(task.DeviceIDs)),
		Metadata:  make(map[string]interface{}),
	}

	// Check if task has already been cancelled
	select {
	case <-task.Context.Done():
		result.Status = TaskStatusCancelled
		result.Error = task.Context.Err()
		p.handleTaskResult(task, result)
		return
	default:
	}

	// Execute task based on type
	var err error
	switch task.Type {
	case TaskTypeCommand:
		err = p.executeCommandTask(task, result)
	case TaskTypeConfig:
		err = p.executeConfigTask(task, result)
	case TaskTypeBackup:
		err = p.executeBackupTask(task, result)
	case TaskTypeHealthCheck:
		err = p.executeHealthCheckTask(task, result)
	case TaskTypeDiscovery:
		err = p.executeDiscoveryTask(task, result)
	case TaskTypeBulkOperation:
		err = p.executeBulkOperationTask(task, result)
	default:
		err = fmt.Errorf("unknown task type: %s", task.Type)
	}

	// Complete task result
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Error = err

	if err != nil {
		result.Status = TaskStatusFailed
		atomic.AddInt64(&p.metrics.TasksFailed, 1)

		// Check if task should be retried
		if p.shouldRetryTask(task, result) {
			p.retryTask(task, result)
			return
		}
	} else {
		result.Status = TaskStatusCompleted
		atomic.AddInt64(&p.metrics.TasksCompleted, 1)
	}

	// Handle task result
	p.handleTaskResult(task, result)

	// Update metrics
	p.updateTaskMetrics(result)

	p.logger.Debug("Task completed",
		"task_id", task.ID,
		"worker_id", worker.id,
		"status", result.Status,
		"duration", result.Duration,
	)
}

// executeCommandTask executes a command task on multiple devices
func (p *WorkerPool) executeCommandTask(task Task, result *TaskResult) error {
	// Get connection pool
	connectionPool := p.getConnectionPool()

	// Execute commands on each device
	for _, deviceID := range task.DeviceIDs {
		deviceResult := DeviceResult{
			DeviceID: deviceID,
			Commands: make([]CommandResult, 0, len(task.Commands)),
			Status:   DeviceStatusSuccess,
		}

		startTime := time.Now()

		// Check circuit breaker for this device
		deviceKey := fmt.Sprintf("device_%d", deviceID)
		if !p.checkCircuitBreaker(deviceKey) {
			deviceResult.Status = DeviceStatusSkipped
			deviceResult.Error = errors.New("circuit breaker open")
			result.Results = append(result.Results, deviceResult)
			continue
		}

		// Get device connection
		device, err := p.getDevice(deviceID)
		if err != nil {
			deviceResult.Status = DeviceStatusFailed
			deviceResult.Error = err
			p.recordCircuitBreakerFailure(deviceKey)
			result.Results = append(result.Results, deviceResult)
			continue
		}

		// Get connection
		conn, err := connectionPool.GetConnection(task.Context, device, p.getCredentials(task.SessionID))
		if err != nil {
			deviceResult.Status = DeviceStatusFailed
			deviceResult.Error = err
			p.recordCircuitBreakerFailure(deviceKey)
			result.Results = append(result.Results, deviceResult)
			continue
		}

		deviceResult.ConnectionID = conn.connectionID
		deviceResult.Hostname = device.Hostname

		// Execute each command
		for _, command := range task.Commands {
			cmdResult, err := p.executeCommandWithContext(task.Context, conn, command)
			if err != nil {
				deviceResult.Status = DeviceStatusFailed
				deviceResult.Error = err
				break
			}
			deviceResult.Commands = append(deviceResult.Commands, *cmdResult)
		}

		// Return connection to pool
		connectionPool.ReturnConnection(conn)

		// Record success/failure for circuit breaker
		if deviceResult.Status == DeviceStatusSuccess {
			p.recordCircuitBreakerSuccess(deviceKey)
		} else {
			p.recordCircuitBreakerFailure(deviceKey)
		}

		deviceResult.Duration = time.Since(startTime)
		result.Results = append(result.Results, deviceResult)

		// Check for task cancellation
		select {
		case <-task.Context.Done():
			return task.Context.Err()
		default:
		}
	}

	return nil
}

// Additional task execution methods would be implemented here...
// (executeConfigTask, executeBackupTask, etc.)

// Shutdown gracefully shuts down the worker pool
func (p *WorkerPool) Shutdown(ctx context.Context) error {
	p.logger.Info("Shutting down worker pool")

	// Signal shutdown to all workers
	close(p.shutdownChan)

	// Stop accepting new tasks
	p.cancel()

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("All workers shut down gracefully")
	case <-ctx.Done():
		p.logger.Warn("Worker shutdown timed out, some tasks may be incomplete")
		return ctx.Err()
	}

	// Close channels
	close(p.taskQueue)

	return nil
}

// Helper methods and additional functionality would continue...

// TaskCallback defines a callback function for task completion
type TaskCallback func(result *TaskResult)

// RetryPolicy defines retry behavior for failed tasks
type RetryPolicy struct {
	MaxAttempts    int
	BackoffMin     time.Duration
	BackoffMax     time.Duration
	BackoffFactor  float64
	RetryableErrors []string
}