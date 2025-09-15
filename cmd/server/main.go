package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/junoscommander/junoscommander/internal/api"
	"github.com/junoscommander/junoscommander/internal/auth"
	"github.com/junoscommander/junoscommander/internal/cache"
	"github.com/junoscommander/junoscommander/internal/config"
	"github.com/junoscommander/junoscommander/internal/database"
	"github.com/junoscommander/junoscommander/internal/device"
	"github.com/junoscommander/junoscommander/internal/health"
	"github.com/junoscommander/junoscommander/internal/lock"
	"github.com/junoscommander/junoscommander/internal/logger"
	"github.com/junoscommander/junoscommander/internal/metrics"
	"github.com/junoscommander/junoscommander/internal/shutdown"
	"github.com/junoscommander/junoscommander/internal/ssh"
	"github.com/junoscommander/junoscommander/internal/task"
	"github.com/junoscommander/junoscommander/internal/web"
	"go.uber.org/zap"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found, using environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize structured logger
	var baseLogger *zap.Logger
	if cfg.Server.Mode == "production" {
		baseLogger, err = logger.NewProductionLogger(cfg.Logging.Output)
	} else {
		baseLogger, err = logger.NewDevelopmentLogger()
	}
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer baseLogger.Sync()

	// Create specialized loggers
	securityLogger := logger.NewSecurityLogger(baseLogger)
	auditLogger := logger.NewAuditLogger(baseLogger)
	performanceLogger := logger.NewPerformanceLogger(baseLogger)
	httpLogger := logger.NewHTTPLogger(baseLogger)

	// Generate instance ID for distributed operations
	instanceID := uuid.New().String()
	baseLogger.Info("Starting JunosCommander",
		zap.String("instance_id", instanceID),
		zap.String("version", "1.0.0"),
		zap.String("mode", cfg.Server.Mode))

	// Initialize shutdown manager
	shutdownManager := shutdown.NewManager(30*time.Second, baseLogger)
	shutdownManager.Listen()

	// Initialize connection drainer
	connDrainer := shutdown.NewConnectionDrainer(baseLogger)

	// Initialize database
	var db *sql.DB
	var postgresDB *database.PostgresDB

	if cfg.Database.Type == "postgres" {
		pgConfig := database.PostgresConfig{
			Host:            cfg.Database.Host,
			Port:            cfg.Database.Port,
			Database:        cfg.Database.Database,
			Username:        cfg.Database.Username,
			Password:        cfg.Database.Password,
			SSLMode:         cfg.Database.SSLMode,
			MaxOpenConns:    cfg.Database.MaxConnections,
			MaxIdleConns:    cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
			ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
		}

		postgresDB, err = database.NewPostgresDB(pgConfig, baseLogger)
		if err != nil {
			baseLogger.Fatal("Failed to initialize PostgreSQL database", zap.Error(err))
		}
		db = postgresDB.DB.DB

		// Run PostgreSQL migrations
		if err := postgresDB.MigratePostgres(); err != nil {
			baseLogger.Fatal("Failed to run PostgreSQL migrations", zap.Error(err))
		}

		shutdownManager.Register("postgres-db", func(ctx context.Context) error {
			return postgresDB.Close()
		})
	} else {
		// SQLite fallback
		db, err = database.Initialize(cfg.Database.Path)
		if err != nil {
			baseLogger.Fatal("Failed to initialize SQLite database", zap.Error(err))
		}

		// Run SQLite migrations
		if err := database.Migrate(db); err != nil {
			baseLogger.Fatal("Failed to run SQLite migrations", zap.Error(err))
		}

		shutdownManager.Register("sqlite-db", func(ctx context.Context) error {
			return db.Close()
		})
	}

	// Initialize Redis
	redisClient, err := cache.NewRedisClient(cache.RedisConfig{
		Address:      cfg.Redis.Address,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		MaxRetries:   cfg.Redis.MaxRetries,
	}, baseLogger)
	if err != nil {
		baseLogger.Fatal("Failed to initialize Redis client", zap.Error(err))
	}

	shutdownManager.Register("redis", func(ctx context.Context) error {
		return redisClient.Close()
	})

	// Initialize metrics
	metricsInstance := metrics.NewMetrics(baseLogger)
	metricsWrapper := metrics.NewMetricsWrapper(metricsInstance)

	// Start metrics collection
	ctx, cancel := context.WithCancel(context.Background())
	go metricsInstance.StartMetricsCollection(ctx, db)

	shutdownManager.Register("metrics", func(shutdownCtx context.Context) error {
		cancel()
		return nil
	})

	// Initialize health service
	healthService := health.NewHealthService("1.0.0", baseLogger)

	// Register health checkers
	healthService.RegisterChecker(health.NewDatabaseChecker("database", db))
	healthService.RegisterChecker(health.NewRedisChecker("redis", redisClient.HealthCheck))
	healthService.RegisterChecker(health.NewDiskSpaceChecker("disk", "./data", 1024*1024*100)) // 100MB threshold

	// Initialize distributed locking
	var lockProvider lock.DistributedLock
	if cfg.Database.Type == "postgres" {
		lockProvider = lock.NewDatabaseLockProvider(postgresDB, instanceID, baseLogger)
	} else {
		// Use Redis for locking with SQLite
		lockProvider = lock.NewRedisLockProvider(redisClient, instanceID, baseLogger)
	}

	lockManager := lock.NewLockManager(lockProvider, baseLogger)

	// Initialize session store (in-memory for now)
	sessionStore := auth.NewSessionStore(cfg.Session.Timeout)

	// Initialize components
	authManager := auth.NewManager(cfg, baseLogger)
	deviceManager := device.NewManager(db, baseLogger)
	sshPool := ssh.NewConnectionPool(&cfg.SSH, baseLogger)
	taskExecutor := task.NewExecutor(&cfg.Task, sshPool, deviceManager, baseLogger)

	// Start background workers
	taskExecutor.Start()
	shutdownManager.Register("task-executor", func(ctx context.Context) error {
		taskExecutor.Stop()
		return nil
	})

	// Start lock renewal process
	go lockManager.StartRenewalProcess(ctx, 30*time.Second)

	shutdownManager.Register("lock-manager", func(shutdownCtx context.Context) error {
		return lockManager.ReleaseAll(shutdownCtx)
	})

	// Setup Gin router
	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(metricsInstance.HTTPMiddleware())

	// Custom logging middleware
	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		httpLogger.LogRequest(
			c.Request.Context(),
			c.Request.Method,
			c.Request.URL.Path,
			c.Request.UserAgent(),
			c.ClientIP(),
			c.Writer.Status(),
			duration,
			int64(c.Writer.Size()),
		)
	})

	// Load HTML templates
	router.LoadHTMLGlob("web/templates/*.html")

	// Setup CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health check endpoints
	router.GET("/health", healthService.HealthHandler())
	router.GET("/ready", healthService.ReadinessHandler())
	router.GET("/live", healthService.LivenessHandler())

	// Metrics endpoint
	if cfg.Metrics.Enabled {
		router.GET(cfg.Metrics.Path, gin.WrapH(metricsInstance.Handler()))
	}

	// Debug endpoints (only in development)
	if cfg.Server.Mode == "development" {
		router.GET("/debug/locks", func(c *gin.Context) {
			c.JSON(200, gin.H{"instance_id": instanceID})
		})
	}

	// Static files
	router.Static("/static", "./web/static")

	// Initialize API routes
	apiHandler := api.NewHandler(cfg, authManager, sessionStore, deviceManager, taskExecutor, baseLogger)
	apiGroup := router.Group("/api/v1")
	{
		// Authentication endpoints
		apiGroup.POST("/auth/login", apiHandler.Login)
		apiGroup.POST("/auth/logout", apiHandler.Logout)

		// Protected routes
		protected := apiGroup.Group("/")
		protected.Use(auth.Middleware(sessionStore))
		{
			// Device endpoints
			protected.GET("/devices", apiHandler.ListDevices)
			protected.POST("/devices", apiHandler.CreateDevice)
			protected.GET("/devices/:id", apiHandler.GetDevice)
			protected.PUT("/devices/:id", apiHandler.UpdateDevice)
			protected.DELETE("/devices/:id", apiHandler.DeleteDevice)
			protected.POST("/devices/bulk", apiHandler.BulkImportDevices)

			// Task endpoints
			protected.POST("/tasks/execute", apiHandler.ExecuteTask)
			protected.GET("/tasks/:id", apiHandler.GetTaskStatus)
			protected.GET("/tasks/:id/output", apiHandler.GetTaskOutput)
			protected.GET("/tasks/history", apiHandler.GetTaskHistory)

			// Configuration endpoints
			protected.POST("/config/push", apiHandler.PushConfiguration)
			protected.POST("/config/validate", apiHandler.ValidateConfiguration)
		}
	}

	// WebSocket endpoint for real-time updates
	router.GET("/ws/tasks", apiHandler.TaskWebSocket)

	// Web UI routes
	webHandler := web.NewHandler(cfg, authManager, sessionStore, deviceManager, taskExecutor, baseLogger)
	router.GET("/", webHandler.Index)
	router.GET("/login", webHandler.LoginPage)
	router.POST("/login", webHandler.Login)
	router.GET("/logout", webHandler.Logout)

	// Protected web routes
	webGroup := router.Group("/")
	webGroup.Use(auth.WebMiddleware(sessionStore))
	{
		webGroup.GET("/dashboard", webHandler.Dashboard)
		webGroup.GET("/devices", webHandler.DevicesPage)
		webGroup.GET("/tasks", webHandler.TasksPage)
		webGroup.GET("/settings", webHandler.SettingsPage)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Register server shutdown
	shutdownManager.Register("http-server", func(shutdownCtx context.Context) error {
		baseLogger.Info("Stopping HTTP server...")

		// Start connection draining
		drainCtx, drainCancel := context.WithTimeout(shutdownCtx, 15*time.Second)
		defer drainCancel()

		if err := connDrainer.WaitForDrain(drainCtx); err != nil {
			baseLogger.Warn("Connection draining incomplete", zap.Error(err))
		}

		return srv.Shutdown(shutdownCtx)
	})

	// Start server in goroutine
	go func() {
		baseLogger.Info("Starting HTTP server",
			zap.String("host", cfg.Server.Host),
			zap.String("port", cfg.Server.Port),
			zap.String("instance_id", instanceID))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			baseLogger.Error("HTTP server error", zap.Error(err))
			shutdownManager.Shutdown()
		}
	}()

	// Suppress unused variables for now
	_ = securityLogger
	_ = auditLogger
	_ = performanceLogger
	_ = metricsWrapper

	// Wait for shutdown signal
	baseLogger.Info("Server started successfully. Waiting for shutdown signal...")
	shutdownManager.Wait()
	baseLogger.Info("Server shutdown complete")
}