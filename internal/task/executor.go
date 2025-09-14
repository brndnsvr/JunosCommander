package task

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/junoscommander/junoscommander/internal/auth"
	"github.com/junoscommander/junoscommander/internal/config"
	"github.com/junoscommander/junoscommander/internal/database"
	"github.com/junoscommander/junoscommander/internal/device"
	"github.com/junoscommander/junoscommander/internal/ssh"
	"go.uber.org/zap"
)

// TaskType represents the type of task
type TaskType string

const (
	TaskGetVersion    TaskType = "get_version"
	TaskGetConfig     TaskType = "get_config"
	TaskGetInterfaces TaskType = "get_interfaces"
	TaskGetRoutes     TaskType = "get_routes"
	TaskHealthCheck   TaskType = "health_check"
	TaskCustom        TaskType = "custom"
)

// TaskStatus represents the status of a task
type TaskStatus string

const (
	TaskStatusQueued    TaskStatus = "queued"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
)

// Task represents a task to be executed
type Task struct {
	ID         string                 `json:"id"`
	Type       TaskType               `json:"type"`
	DeviceIDs  []int                  `json:"device_ids"`
	Parameters map[string]interface{} `json:"parameters"`
	Username   string                 `json:"username"`
	Status     TaskStatus             `json:"status"`
	StartedAt  time.Time              `json:"started_at"`
	CreatedAt  time.Time              `json:"created_at"`
}

// TaskResult represents the result of a task execution
type TaskResult struct {
	TaskID        string         `json:"task_id"`
	DeviceID      int            `json:"device_id"`
	Hostname      string         `json:"hostname"`
	Status        string         `json:"status"`
	Output        string         `json:"output"`
	Error         string         `json:"error"`
	ExecutionTime time.Duration  `json:"execution_time"`
}

// Executor handles task execution
type Executor struct {
	config        *config.TaskConfig
	sshPool       *ssh.ConnectionPool
	deviceManager *device.Manager
	logger        *zap.Logger
	taskQueue     chan *Task
	results       map[string][]*TaskResult
	resultsMu     sync.RWMutex
	workers       int
	wg            sync.WaitGroup
	stopCh        chan struct{}
}

// NewExecutor creates a new task executor
func NewExecutor(cfg *config.TaskConfig, sshPool *ssh.ConnectionPool, deviceManager *device.Manager, logger *zap.Logger) *Executor {
	return &Executor{
		config:        cfg,
		sshPool:       sshPool,
		deviceManager: deviceManager,
		logger:        logger,
		taskQueue:     make(chan *Task, cfg.QueueSize),
		results:       make(map[string][]*TaskResult),
		workers:       cfg.WorkerPoolSize,
		stopCh:        make(chan struct{}),
	}
}

// Start starts the task executor workers
func (e *Executor) Start() {
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}
	e.logger.Info("Task executor started", zap.Int("workers", e.workers))
}

// Stop stops the task executor
func (e *Executor) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	close(e.taskQueue)
	e.logger.Info("Task executor stopped")
}

// worker processes tasks from the queue
func (e *Executor) worker(id int) {
	defer e.wg.Done()

	for {
		select {
		case task := <-e.taskQueue:
			if task != nil {
				e.processTask(task)
			}
		case <-e.stopCh:
			return
		}
	}
}

// generateTaskID generates a random task ID
func generateTaskID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ExecuteTask queues a task for execution
func (e *Executor) ExecuteTask(taskType TaskType, deviceIDs []int, username string, credentials *auth.Credentials, parameters map[string]interface{}) (*Task, error) {
	task := &Task{
		ID:         generateTaskID(),
		Type:       taskType,
		DeviceIDs:  deviceIDs,
		Parameters: parameters,
		Username:   username,
		Status:     TaskStatusQueued,
		CreatedAt:  time.Now(),
	}

	// Store credentials in parameters (they're already encrypted in session)
	task.Parameters["_credentials"] = credentials

	// Queue task
	select {
	case e.taskQueue <- task:
		e.logger.Info("Task queued",
			zap.String("task_id", task.ID),
			zap.String("type", string(task.Type)),
			zap.Int("devices", len(deviceIDs)))
		return task, nil
	default:
		return nil, fmt.Errorf("task queue is full")
	}
}

// processTask processes a single task
func (e *Executor) processTask(task *Task) {
	task.Status = TaskStatusRunning
	task.StartedAt = time.Now()

	// Get credentials from parameters
	credentials, ok := task.Parameters["_credentials"].(*auth.Credentials)
	if !ok {
		e.logger.Error("Missing credentials for task", zap.String("task_id", task.ID))
		task.Status = TaskStatusFailed
		return
	}

	// Get devices
	devices, err := e.deviceManager.GetDevicesByIDs(task.DeviceIDs)
	if err != nil {
		e.logger.Error("Failed to get devices",
			zap.String("task_id", task.ID),
			zap.Error(err))
		task.Status = TaskStatusFailed
		return
	}

	// Execute task on each device
	var wg sync.WaitGroup
	resultsChan := make(chan *TaskResult, len(devices))

	for _, dev := range devices {
		wg.Add(1)
		go func(d *database.Device) {
			defer wg.Done()
			result := e.executeOnDevice(task, d, credentials)
			resultsChan <- result
		}(dev)
	}

	// Wait for all devices to complete
	wg.Wait()
	close(resultsChan)

	// Collect results
	var results []*TaskResult
	for result := range resultsChan {
		results = append(results, result)
	}

	// Store results
	e.resultsMu.Lock()
	e.results[task.ID] = results
	e.resultsMu.Unlock()

	task.Status = TaskStatusCompleted
	e.logger.Info("Task completed",
		zap.String("task_id", task.ID),
		zap.Duration("duration", time.Since(task.StartedAt)))
}

// executeOnDevice executes a task on a single device
func (e *Executor) executeOnDevice(task *Task, device *database.Device, credentials *auth.Credentials) *TaskResult {
	startTime := time.Now()
	result := &TaskResult{
		TaskID:   task.ID,
		DeviceID: device.ID,
		Hostname: device.Hostname,
		Status:   "success",
	}

	// Get SSH connection
	conn, err := e.sshPool.GetConnection(device.Hostname, device.IPAddress, credentials.Username, credentials.Password)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Failed to connect: %v", err)
		result.ExecutionTime = time.Since(startTime)
		return result
	}
	defer e.sshPool.ReturnConnection(conn)

	// Execute command based on task type
	command := e.getCommandForTask(task.Type, device.DeviceType)
	if command == "" {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Unsupported task type: %s", task.Type)
		result.ExecutionTime = time.Since(startTime)
		return result
	}

	// Execute command
	output, err := conn.ExecuteCommand(command)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Command execution failed: %v", err)
		result.Output = output
	} else {
		result.Output = output
	}

	result.ExecutionTime = time.Since(startTime)
	return result
}

// getCommandForTask returns the command to execute for a task type
func (e *Executor) getCommandForTask(taskType TaskType, deviceType string) string {
	commands := map[TaskType]map[string]string{
		TaskGetVersion: {
			"junos":      "show version",
			"cisco_ios":  "show version",
			"cisco_nxos": "show version",
			"arista_eos": "show version",
		},
		TaskGetConfig: {
			"junos":      "show configuration",
			"cisco_ios":  "show running-config",
			"cisco_nxos": "show running-config",
			"arista_eos": "show running-config",
		},
		TaskGetInterfaces: {
			"junos":      "show interfaces terse",
			"cisco_ios":  "show ip interface brief",
			"cisco_nxos": "show ip interface brief",
			"arista_eos": "show ip interface brief",
		},
		TaskGetRoutes: {
			"junos":      "show route",
			"cisco_ios":  "show ip route",
			"cisco_nxos": "show ip route",
			"arista_eos": "show ip route",
		},
		TaskHealthCheck: {
			"junos":      "show system uptime | show system alarms",
			"cisco_ios":  "show processes cpu | show memory",
			"cisco_nxos": "show processes cpu | show system resources",
			"arista_eos": "show processes top | show version",
		},
	}

	if cmdMap, ok := commands[taskType]; ok {
		if cmd, ok := cmdMap[deviceType]; ok {
			return cmd
		}
		// Default to junos if device type not found
		if cmd, ok := cmdMap["junos"]; ok {
			return cmd
		}
	}

	return ""
}

// GetTaskStatus returns the status of a task
func (e *Executor) GetTaskStatus(taskID string) (*Task, []*TaskResult, error) {
	e.resultsMu.RLock()
	results, exists := e.results[taskID]
	e.resultsMu.RUnlock()

	if !exists {
		return nil, nil, fmt.Errorf("task not found")
	}

	// TODO: Get actual task from storage
	task := &Task{
		ID:     taskID,
		Status: TaskStatusCompleted,
	}

	return task, results, nil
}

// GetTaskResults returns the results of a task
func (e *Executor) GetTaskResults(taskID string) ([]*TaskResult, error) {
	e.resultsMu.RLock()
	results, exists := e.results[taskID]
	e.resultsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("task results not found")
	}

	return results, nil
}