package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/junoscommander/junoscommander/internal/auth"
	"github.com/junoscommander/junoscommander/internal/config"
	"github.com/junoscommander/junoscommander/internal/database"
	"github.com/junoscommander/junoscommander/internal/device"
	"github.com/junoscommander/junoscommander/internal/task"
	"go.uber.org/zap"
)

// Handler handles API requests
type Handler struct {
	config        *config.Config
	authManager   *auth.Manager
	sessionStore  *auth.SessionStore
	deviceManager *device.Manager
	taskExecutor  *task.Executor
	logger        *zap.Logger
	upgrader      websocket.Upgrader
}

// NewHandler creates a new API handler
func NewHandler(
	cfg *config.Config,
	authManager *auth.Manager,
	sessionStore *auth.SessionStore,
	deviceManager *device.Manager,
	taskExecutor *task.Executor,
	logger *zap.Logger,
) *Handler {
	return &Handler{
		config:        cfg,
		authManager:   authManager,
		sessionStore:  sessionStore,
		deviceManager: deviceManager,
		taskExecutor:  taskExecutor,
		logger:        logger,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // TODO: Implement proper origin checking
			},
		},
	}
}

// Login handles user authentication
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Authenticate user
	user, err := h.authManager.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		h.logger.Warn("Authentication failed",
			zap.String("username", req.Username),
			zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create session
	credentials := &auth.Credentials{
		Username: req.Username,
		Password: req.Password,
	}

	session, token, err := h.sessionStore.CreateSession(user, credentials)
	if err != nil {
		h.logger.Error("Failed to create session",
			zap.String("username", req.Username),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	h.logger.Info("User logged in",
		zap.String("username", req.Username),
		zap.String("session_id", session.ID))

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": session.ExpiresAt,
		"user":       user,
	})
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	session, exists := c.Get("session")
	if exists {
		if s, ok := session.(*auth.Session); ok {
			h.sessionStore.DeleteSession(s.ID)
			h.logger.Info("User logged out", zap.String("username", s.Username))
		}
	}

	c.JSON(http.StatusNoContent, nil)
}

// ListDevices returns a list of devices
func (h *Handler) ListDevices(c *gin.Context) {
	filters := make(map[string]string)
	filters["site"] = c.Query("site")
	filters["type"] = c.Query("type")
	filters["status"] = c.Query("status")
	filters["tag"] = c.Query("tag")

	devices, err := h.deviceManager.ListDevices(filters)
	if err != nil {
		h.logger.Error("Failed to list devices", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list devices"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items": devices,
		"total": len(devices),
	})
}

// GetDevice returns a single device
func (h *Handler) GetDevice(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	device, err := h.deviceManager.GetDevice(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	c.JSON(http.StatusOK, device)
}

// CreateDevice creates a new device
func (h *Handler) CreateDevice(c *gin.Context) {
	var device database.Device
	if err := c.ShouldBindJSON(&device); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Set default status if not provided
	if device.Status == "" {
		device.Status = "active"
	}

	if err := h.deviceManager.CreateDevice(&device); err != nil {
		h.logger.Error("Failed to create device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, device)
}

// UpdateDevice updates an existing device
func (h *Handler) UpdateDevice(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	var device database.Device
	if err := c.ShouldBindJSON(&device); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	device.ID = id
	if err := h.deviceManager.UpdateDevice(&device); err != nil {
		h.logger.Error("Failed to update device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update device"})
		return
	}

	c.JSON(http.StatusOK, device)
}

// DeleteDevice deletes a device
func (h *Handler) DeleteDevice(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	if err := h.deviceManager.DeleteDevice(id); err != nil {
		h.logger.Error("Failed to delete device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete device"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// BulkImportDevices imports multiple devices
func (h *Handler) BulkImportDevices(c *gin.Context) {
	// TODO: Implement bulk import
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ExecuteTask executes a task on devices
func (h *Handler) ExecuteTask(c *gin.Context) {
	var req struct {
		TaskType   string                 `json:"task_type" binding:"required"`
		DeviceIDs  []int                  `json:"device_ids" binding:"required"`
		Parameters map[string]interface{} `json:"parameters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get session and credentials
	session := c.MustGet("session").(*auth.Session)
	credentials, err := h.sessionStore.GetCredentials(session.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get credentials"})
		return
	}

	// Execute task
	taskObj, err := h.taskExecutor.ExecuteTask(
		task.TaskType(req.TaskType),
		req.DeviceIDs,
		session.Username,
		credentials,
		req.Parameters,
	)

	if err != nil {
		h.logger.Error("Failed to execute task", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to execute task"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"task_id":      taskObj.ID,
		"status":       taskObj.Status,
		"device_count": len(req.DeviceIDs),
		"started_at":   taskObj.StartedAt,
	})
}

// GetTaskStatus returns the status of a task
func (h *Handler) GetTaskStatus(c *gin.Context) {
	taskID := c.Param("id")

	taskObj, results, err := h.taskExecutor.GetTaskStatus(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	// Calculate progress
	completed := 0
	failed := 0
	for _, result := range results {
		if result.Status == "success" {
			completed++
		} else {
			failed++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskObj.ID,
		"status":  taskObj.Status,
		"progress": gin.H{
			"total":     len(results),
			"completed": completed,
			"failed":    failed,
		},
	})
}

// GetTaskOutput returns the output of a task
func (h *Handler) GetTaskOutput(c *gin.Context) {
	taskID := c.Param("id")

	results, err := h.taskExecutor.GetTaskResults(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task results not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"task_id": taskID,
		"outputs": results,
	})
}

// GetTaskHistory returns task execution history
func (h *Handler) GetTaskHistory(c *gin.Context) {
	// TODO: Implement task history from database
	c.JSON(http.StatusOK, gin.H{
		"items": []interface{}{},
		"total": 0,
	})
}

// PushConfiguration pushes configuration to devices
func (h *Handler) PushConfiguration(c *gin.Context) {
	// TODO: Implement configuration push
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ValidateConfiguration validates configuration syntax
func (h *Handler) ValidateConfiguration(c *gin.Context) {
	// TODO: Implement configuration validation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// TaskWebSocket handles WebSocket connections for real-time task updates
func (h *Handler) TaskWebSocket(c *gin.Context) {
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	// TODO: Implement WebSocket task updates
	for {
		messageType, _, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Echo message back for now
		err = conn.WriteMessage(messageType, []byte(`{"type":"pong"}`))
		if err != nil {
			break
		}
	}
}