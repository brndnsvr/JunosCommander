package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// Initialize creates and returns a database connection
func Initialize(dbPath string) (*sql.DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// Migrate runs database migrations
func Migrate(db *sql.DB) error {
	// Create devices table
	createDevicesTable := `
	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname VARCHAR(255) UNIQUE NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		site_name VARCHAR(100) NOT NULL,
		device_type VARCHAR(50) NOT NULL,
		device_sub_type VARCHAR(50),
		tags TEXT,
		sw_version VARCHAR(100),
		model VARCHAR(100),
		serial_number VARCHAR(100),
		last_seen TIMESTAMP,
		last_backup TIMESTAMP,
		status VARCHAR(20) DEFAULT 'active',
		notes TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createDevicesTable); err != nil {
		return fmt.Errorf("failed to create devices table: %w", err)
	}

	// Create device_credentials table
	createCredentialsTable := `
	CREATE TABLE IF NOT EXISTS device_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL,
		credential_type VARCHAR(20),
		username VARCHAR(100),
		encrypted_password TEXT,
		ssh_key_path VARCHAR(255),
		enable_password TEXT,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	);`

	if _, err := db.Exec(createCredentialsTable); err != nil {
		return fmt.Errorf("failed to create device_credentials table: %w", err)
	}

	// Create task_history table
	createTaskHistoryTable := `
	CREATE TABLE IF NOT EXISTS task_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id VARCHAR(36) NOT NULL,
		device_id INTEGER NOT NULL,
		task_type VARCHAR(50) NOT NULL,
		task_name VARCHAR(100),
		executed_by VARCHAR(100) NOT NULL,
		execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		status VARCHAR(20) NOT NULL,
		output TEXT,
		error_message TEXT,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	);`

	if _, err := db.Exec(createTaskHistoryTable); err != nil {
		return fmt.Errorf("failed to create task_history table: %w", err)
	}

	// Create config_backups table
	createConfigBackupsTable := `
	CREATE TABLE IF NOT EXISTS config_backups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL,
		config_type VARCHAR(20),
		config_data TEXT NOT NULL,
		backup_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		backed_up_by VARCHAR(100),
		FOREIGN KEY (device_id) REFERENCES devices(id)
	);`

	if _, err := db.Exec(createConfigBackupsTable); err != nil {
		return fmt.Errorf("failed to create config_backups table: %w", err)
	}

	// Create audit_log table
	createAuditLogTable := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user VARCHAR(100) NOT NULL,
		action VARCHAR(50) NOT NULL,
		resource_type VARCHAR(50),
		resource_id VARCHAR(100),
		details TEXT,
		ip_address VARCHAR(45),
		session_id VARCHAR(36),
		success BOOLEAN DEFAULT 1
	);`

	if _, err := db.Exec(createAuditLogTable); err != nil {
		return fmt.Errorf("failed to create audit_log table: %w", err)
	}

	// Create indices for better performance
	indices := []string{
		"CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);",
		"CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site_name);",
		"CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);",
		"CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_device ON task_history(device_id);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_user ON task_history(executed_by);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);",
	}

	for _, index := range indices {
		if _, err := db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}