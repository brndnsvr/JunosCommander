package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Session  SessionConfig
	Auth     AuthConfig
	SSH      SSHConfig
	Task     TaskConfig
	Logging  LoggingConfig
	Metrics  MetricsConfig
	Health   HealthConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host string
	Port string
	Mode string // development or production
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type           string // sqlite or postgres
	Path           string // For SQLite
	Host           string // For PostgreSQL
	Port           int    // For PostgreSQL
	Database       string // For PostgreSQL
	Username       string // For PostgreSQL
	Password       string // For PostgreSQL
	SSLMode        string // For PostgreSQL
	MaxConnections int
	MaxIdleConns   int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Address      string
	Password     string
	DB           int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
}

// SessionConfig holds session configuration
type SessionConfig struct {
	Timeout       time.Duration
	EncryptionKey string
	JWTSecret     string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	LDAPServer     string
	LDAPPort       int
	LDAPBaseDN     string
	ServiceUser    string
	ServicePassword string
	UseTLS         bool
}

// SSHConfig holds SSH configuration
type SSHConfig struct {
	DefaultTimeout     time.Duration
	MaxConnections     int
	ConnectionPoolSize int
	RetryAttempts      int
	RetryDelay         time.Duration
	KeepaliveInterval  time.Duration
}

// TaskConfig holds task execution configuration
type TaskConfig struct {
	MaxParallel     int
	WorkerPoolSize  int
	QueueSize       int
	DefaultTimeout  time.Duration
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level        string
	Format       string // json or console
	Output       string // stdout, stderr, or file path
	EnableCaller bool
	Environment  string
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled  bool
	Path     string
	Interval time.Duration
}

// HealthConfig holds health check configuration
type HealthConfig struct {
	Enabled bool
	Timeout time.Duration
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
			Port: getEnv("SERVER_PORT", "8080"),
			Mode: getEnv("SERVER_MODE", "development"),
		},
		Database: DatabaseConfig{
			Type:            getEnv("DB_TYPE", "sqlite"),
			Path:            getEnv("DB_PATH", "./data/junoscommander.db"),
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			Database:        getEnv("DB_NAME", "junoscommander"),
			Username:        getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxConnections:  getEnvAsInt("DB_MAX_CONNECTIONS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNECTIONS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 1*time.Hour),
			ConnMaxIdleTime: getEnvAsDuration("DB_CONN_MAX_IDLE_TIME", 10*time.Minute),
		},
		Redis: RedisConfig{
			Address:      getEnv("REDIS_ADDRESS", "localhost:6379"),
			Password:     getEnv("REDIS_PASSWORD", ""),
			DB:           getEnvAsInt("REDIS_DB", 0),
			DialTimeout:  getEnvAsDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:  getEnvAsDuration("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout: getEnvAsDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
			PoolSize:     getEnvAsInt("REDIS_POOL_SIZE", 10),
			MinIdleConns: getEnvAsInt("REDIS_MIN_IDLE_CONNS", 3),
			MaxRetries:   getEnvAsInt("REDIS_MAX_RETRIES", 3),
		},
		Session: SessionConfig{
			Timeout:       getEnvAsDuration("SESSION_TIMEOUT", 8*time.Hour),
			EncryptionKey: getEnv("SESSION_KEY", "change-this-32-byte-key-in-prod!"),
			JWTSecret:     getEnv("JWT_SECRET", "change-this-secret-in-production"),
		},
		Auth: AuthConfig{
			LDAPServer:      getEnv("AD_SERVER", "ldap://localhost:389"),
			LDAPPort:        getEnvAsInt("AD_PORT", 389),
			LDAPBaseDN:      getEnv("AD_BASE_DN", "DC=example,DC=com"),
			ServiceUser:     getEnv("AD_SERVICE_USER", ""),
			ServicePassword: getEnv("AD_SERVICE_PASSWORD", ""),
			UseTLS:         getEnvAsBool("AD_USE_TLS", false),
		},
		SSH: SSHConfig{
			DefaultTimeout:     getEnvAsDuration("SSH_DEFAULT_TIMEOUT", 30*time.Second),
			MaxConnections:     getEnvAsInt("SSH_MAX_CONNECTIONS", 100),
			ConnectionPoolSize: getEnvAsInt("SSH_POOL_SIZE", 10),
			RetryAttempts:      getEnvAsInt("SSH_RETRY_ATTEMPTS", 3),
			RetryDelay:         getEnvAsDuration("SSH_RETRY_DELAY", 5*time.Second),
			KeepaliveInterval:  getEnvAsDuration("SSH_KEEPALIVE_INTERVAL", 30*time.Second),
		},
		Task: TaskConfig{
			MaxParallel:    getEnvAsInt("TASK_MAX_PARALLEL", 20),
			WorkerPoolSize: getEnvAsInt("TASK_WORKER_POOL_SIZE", 50),
			QueueSize:      getEnvAsInt("TASK_QUEUE_SIZE", 1000),
			DefaultTimeout: getEnvAsDuration("TASK_DEFAULT_TIMEOUT", 60*time.Second),
		},
		Logging: LoggingConfig{
			Level:        getEnv("LOG_LEVEL", "info"),
			Format:       getEnv("LOG_FORMAT", "json"),
			Output:       getEnv("LOG_OUTPUT", "stdout"),
			EnableCaller: getEnvAsBool("LOG_ENABLE_CALLER", false),
			Environment:  getEnv("SERVER_MODE", "development"),
		},
		Metrics: MetricsConfig{
			Enabled:  getEnvAsBool("METRICS_ENABLED", true),
			Path:     getEnv("METRICS_PATH", "/metrics"),
			Interval: getEnvAsDuration("METRICS_INTERVAL", 30*time.Second),
		},
		Health: HealthConfig{
			Enabled: getEnvAsBool("HEALTH_ENABLED", true),
			Timeout: getEnvAsDuration("HEALTH_TIMEOUT", 5*time.Second),
		},
	}

	return cfg, nil
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}