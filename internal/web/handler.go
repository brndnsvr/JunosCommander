package web

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/junoscommander/junoscommander/internal/auth"
	"github.com/junoscommander/junoscommander/internal/config"
	"github.com/junoscommander/junoscommander/internal/database"
	"github.com/junoscommander/junoscommander/internal/device"
	"github.com/junoscommander/junoscommander/internal/task"
	"go.uber.org/zap"
)

// Handler handles web UI requests
type Handler struct {
	config        *config.Config
	authManager   *auth.Manager
	sessionStore  *auth.SessionStore
	deviceManager *device.Manager
	taskExecutor  *task.Executor
	logger        *zap.Logger
}

// NewHandler creates a new web handler
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
	}
}

// Index handles the home page
func (h *Handler) Index(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "JunosCommander",
	})
}

// LoginPage renders the login page
func (h *Handler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Login - JunosCommander",
	})
}

// Login handles login form submission
func (h *Handler) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"error": "Username and password are required",
		})
		return
	}

	// Authenticate user
	user, err := h.authManager.AuthenticateUser(username, password)
	if err != nil {
		h.logger.Warn("Authentication failed",
			zap.String("username", username),
			zap.Error(err))
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Create session
	credentials := &auth.Credentials{
		Username: username,
		Password: password,
	}

	session, token, err := h.sessionStore.CreateSession(user, credentials)
	if err != nil {
		h.logger.Error("Failed to create session",
			zap.String("username", username),
			zap.Error(err))
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"error": "Failed to create session",
		})
		return
	}

	// Set session cookie
	c.SetCookie(
		"session_token",
		token,
		int(h.config.Session.Timeout.Seconds()),
		"/",
		"",
		false, // TODO: Set to true for HTTPS
		true,
	)

	h.logger.Info("User logged in via web",
		zap.String("username", username),
		zap.String("session_id", session.ID))

	// Redirect to dashboard
	c.Redirect(http.StatusFound, "/dashboard")
}

// Logout handles logout
func (h *Handler) Logout(c *gin.Context) {
	// Get session from context
	if session, exists := c.Get("session"); exists {
		if s, ok := session.(*auth.Session); ok {
			h.sessionStore.DeleteSession(s.ID)
			h.logger.Info("User logged out via web", zap.String("username", s.Username))
		}
	}

	// Clear cookie
	c.SetCookie("session_token", "", -1, "/", "", false, true)

	// Redirect to login
	c.Redirect(http.StatusFound, "/login")
}

// Dashboard renders the dashboard page
func (h *Handler) Dashboard(c *gin.Context) {
	session := c.MustGet("session").(*auth.Session)

	// Get device count
	devices, _ := h.deviceManager.ListDevices(nil)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":       "Dashboard - JunosCommander",
		"user":        session.User,
		"deviceCount": len(devices),
		"activeTasks": 0, // TODO: Get from task executor
		"lastUpdate":  time.Now().Format("15:04:05"),
	})
}

// DevicesPage renders the devices page
func (h *Handler) DevicesPage(c *gin.Context) {
	session := c.MustGet("session").(*auth.Session)

	// Get filters from query params
	filters := make(map[string]string)
	filters["site"] = c.Query("site")
	filters["type"] = c.Query("type")
	filters["status"] = c.Query("status")

	// Get devices
	devices, err := h.deviceManager.ListDevices(filters)
	if err != nil {
		h.logger.Error("Failed to list devices", zap.Error(err))
		devices = []*database.Device{}
	}

	c.HTML(http.StatusOK, "devices.html", gin.H{
		"title":   "Devices - JunosCommander",
		"user":    session.User,
		"devices": devices,
		"filters": filters,
	})
}

// TasksPage renders the tasks page
func (h *Handler) TasksPage(c *gin.Context) {
	session := c.MustGet("session").(*auth.Session)

	c.HTML(http.StatusOK, "tasks.html", gin.H{
		"title": "Tasks - JunosCommander",
		"user":  session.User,
		"tasks": []interface{}{}, // TODO: Get from task executor
	})
}

// SettingsPage renders the settings page
func (h *Handler) SettingsPage(c *gin.Context) {
	session := c.MustGet("session").(*auth.Session)

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"title": "Settings - JunosCommander",
		"user":  session.User,
	})
}