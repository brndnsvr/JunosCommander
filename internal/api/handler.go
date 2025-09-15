package api

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

	// Try to bind JSON first, then fall back to form data
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&device); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON request"})
			return
		}
	} else {
		// Handle form data (from web UI)
		device.Hostname = c.PostForm("hostname")
		device.IPAddress = c.PostForm("ip_address")
		device.SiteName = c.PostForm("site_name")
		device.DeviceType = c.PostForm("device_type")
		device.Status = c.PostForm("status")

		// Handle optional fields
		if model := c.PostForm("model"); model != "" {
			device.Model = sql.NullString{String: model, Valid: true}
		}
		if tags := c.PostForm("tags"); tags != "" {
			device.Tags = sql.NullString{String: tags, Valid: true}
		}
		if notes := c.PostForm("notes"); notes != "" {
			device.Notes = sql.NullString{String: notes, Valid: true}
		}
		if swVersion := c.PostForm("sw_version"); swVersion != "" {
			device.SWVersion = sql.NullString{String: swVersion, Valid: true}
		}
		if serialNumber := c.PostForm("serial_number"); serialNumber != "" {
			device.SerialNumber = sql.NullString{String: serialNumber, Valid: true}
		}
	}

	// Validate required fields
	if device.Hostname == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Hostname is required"})
		return
	}
	if device.IPAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP address is required"})
		return
	}

	// Validate IP address format
	if !isValidIP(device.IPAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address format"})
		return
	}

	// Set defaults
	if device.Status == "" {
		device.Status = "active"
	}
	if device.SiteName == "" {
		device.SiteName = "Default"
	}
	if device.DeviceType == "" {
		device.DeviceType = "router"
	}

	// Create device in database
	if err := h.deviceManager.CreateDevice(&device); err != nil {
		h.logger.Error("Failed to create device", zap.Error(err))
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create device"})
		}
		return
	}

	h.logger.Info("Device created successfully",
		zap.Int("id", device.ID),
		zap.String("hostname", device.Hostname),
		zap.String("ip", device.IPAddress))

	// Return appropriate response based on request type
	if strings.Contains(contentType, "application/json") {
		c.JSON(http.StatusCreated, device)
	} else {
		// For HTMX requests, return a success message
		c.HTML(http.StatusCreated, "device-row", gin.H{
			"device": device,
			"message": fmt.Sprintf("Device %s created successfully", device.Hostname),
		})
	}
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

// BulkImportDevices imports multiple devices from CSV
func (h *Handler) BulkImportDevices(c *gin.Context) {
	// Handle multipart form file upload
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		h.logger.Error("Failed to get uploaded file", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	// Validate file extension
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File must be a CSV"})
		return
	}

	// Parse CSV
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		h.logger.Error("Failed to parse CSV", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSV format"})
		return
	}

	if len(records) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSV file is empty or only contains headers"})
		return
	}

	// Parse header to get column indices
	headers := records[0]
	columnMap := make(map[string]int)
	for i, header := range headers {
		columnMap[strings.ToLower(strings.TrimSpace(header))] = i
	}

	// Validate required columns
	requiredColumns := []string{"hostname", "ip_address"}
	for _, col := range requiredColumns {
		if _, ok := columnMap[col]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Missing required column: %s", col),
				"required_columns": requiredColumns,
				"optional_columns": []string{"type", "site", "port", "model", "tags", "notes"},
			})
			return
		}
	}

	// Process devices
	var devices []database.Device
	var errors []string
	successCount := 0
	failedCount := 0

	for i, record := range records[1:] { // Skip header row
		lineNum := i + 2 // Account for header and 0-based index

		// Extract values with bounds checking
		getValue := func(colName string) string {
			if idx, ok := columnMap[colName]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		hostname := getValue("hostname")
		ipAddress := getValue("ip_address")

		// Validate required fields
		if hostname == "" || ipAddress == "" {
			errors = append(errors, fmt.Sprintf("Line %d: missing hostname or IP address", lineNum))
			failedCount++
			continue
		}

		// Validate IP address format
		if !isValidIP(ipAddress) {
			errors = append(errors, fmt.Sprintf("Line %d: invalid IP address '%s'", lineNum, ipAddress))
			failedCount++
			continue
		}

		// Create device object
		device := database.Device{
			Hostname:   hostname,
			IPAddress:  ipAddress,
			Status:     "active", // Default status
		}

		// Set optional fields
		if site := getValue("site"); site != "" {
			device.SiteName = site
		} else {
			device.SiteName = "Default" // Default site
		}

		if deviceType := getValue("type"); deviceType != "" {
			device.DeviceType = deviceType
		} else if deviceType := getValue("device_type"); deviceType != "" {
			device.DeviceType = deviceType
		} else {
			device.DeviceType = "router" // Default type
		}

		if model := getValue("model"); model != "" {
			device.Model = sql.NullString{String: model, Valid: true}
		}

		if tags := getValue("tags"); tags != "" {
			device.Tags = sql.NullString{String: tags, Valid: true}
		}

		if notes := getValue("notes"); notes != "" {
			device.Notes = sql.NullString{String: notes, Valid: true}
		}

		devices = append(devices, device)
	}

	// Import devices into database
	for i, device := range devices {
		if err := h.deviceManager.CreateDevice(&device); err != nil {
			lineNum := i + 2
			if strings.Contains(err.Error(), "already exists") {
				errors = append(errors, fmt.Sprintf("Line %d: device '%s' already exists", lineNum, device.Hostname))
			} else {
				errors = append(errors, fmt.Sprintf("Line %d: %s", lineNum, err.Error()))
			}
			failedCount++
		} else {
			successCount++
		}
	}

	// Prepare response
	response := gin.H{
		"total":     len(devices),
		"success":   successCount,
		"failed":    failedCount,
		"processed": successCount + failedCount,
	}

	if len(errors) > 0 {
		response["errors"] = errors
		// Limit errors in response to first 10
		if len(errors) > 10 {
			response["errors"] = append(errors[:10], fmt.Sprintf("... and %d more errors", len(errors)-10))
		}
	}

	statusCode := http.StatusOK
	if successCount == 0 && failedCount > 0 {
		statusCode = http.StatusBadRequest
	} else if failedCount > 0 {
		statusCode = http.StatusPartialContent
	}

	h.logger.Info("Bulk device import completed",
		zap.Int("success", successCount),
		zap.Int("failed", failedCount),
		zap.String("filename", header.Filename))

	c.JSON(statusCode, response)
}

// isValidIP validates an IP address
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
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