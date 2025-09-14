package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// PostgresDB wraps the database connection with PostgreSQL-specific functionality
type PostgresDB struct {
	*sqlx.DB
	logger *zap.Logger
}

// PostgresConfig holds PostgreSQL connection configuration
type PostgresConfig struct {
	Host            string
	Port            int
	Database        string
	Username        string
	Password        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// NewPostgresDB creates a new PostgreSQL database connection
func NewPostgresDB(config PostgresConfig, logger *zap.Logger) (*PostgresDB, error) {
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		config.Host, config.Port, config.Database, config.Username, config.Password, config.SSLMode)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %w", err)
	}

	logger.Info("Successfully connected to PostgreSQL",
		zap.String("host", config.Host),
		zap.Int("port", config.Port),
		zap.String("database", config.Database))

	return &PostgresDB{
		DB:     db,
		logger: logger,
	}, nil
}

// HealthCheck performs a health check on the database
func (pdb *PostgresDB) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var result int
	err := pdb.DB.GetContext(ctx, &result, "SELECT 1")
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

// MigratePostgres runs PostgreSQL-specific migrations
func (pdb *PostgresDB) MigratePostgres() error {
	// Create devices table with PostgreSQL-specific features
	createDevicesTable := `
	CREATE TABLE IF NOT EXISTS devices (
		id SERIAL PRIMARY KEY,
		hostname VARCHAR(255) UNIQUE NOT NULL,
		ip_address INET NOT NULL,
		site_name VARCHAR(100) NOT NULL,
		device_type VARCHAR(50) NOT NULL,
		device_sub_type VARCHAR(50),
		tags TEXT[],
		sw_version VARCHAR(100),
		model VARCHAR(100),
		serial_number VARCHAR(100),
		last_seen TIMESTAMPTZ,
		last_backup TIMESTAMPTZ,
		status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance')),
		notes TEXT,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := pdb.DB.Exec(createDevicesTable); err != nil {
		return fmt.Errorf("failed to create devices table: %w", err)
	}

	// Create device_credentials table
	createCredentialsTable := `
	CREATE TABLE IF NOT EXISTS device_credentials (
		id SERIAL PRIMARY KEY,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		credential_type VARCHAR(20) CHECK (credential_type IN ('password', 'key', 'tacacs')),
		username VARCHAR(100),
		encrypted_password TEXT,
		ssh_key_path VARCHAR(255),
		enable_password TEXT,
		created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := pdb.DB.Exec(createCredentialsTable); err != nil {
		return fmt.Errorf("failed to create device_credentials table: %w", err)
	}

	// Create task_history table with JSONB for flexible data
	createTaskHistoryTable := `
	CREATE TABLE IF NOT EXISTS task_history (
		id SERIAL PRIMARY KEY,
		task_id UUID NOT NULL,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		task_type VARCHAR(50) NOT NULL,
		task_name VARCHAR(100),
		executed_by VARCHAR(100) NOT NULL,
		execution_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
		output TEXT,
		error_message TEXT,
		metadata JSONB,
		duration_ms INTEGER
	);`

	if _, err := pdb.DB.Exec(createTaskHistoryTable); err != nil {
		return fmt.Errorf("failed to create task_history table: %w", err)
	}

	// Create config_backups table
	createConfigBackupsTable := `
	CREATE TABLE IF NOT EXISTS config_backups (
		id SERIAL PRIMARY KEY,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		config_type VARCHAR(20) CHECK (config_type IN ('running', 'candidate', 'startup')),
		config_data TEXT NOT NULL,
		backup_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		backed_up_by VARCHAR(100),
		checksum VARCHAR(64),
		size_bytes INTEGER
	);`

	if _, err := pdb.DB.Exec(createConfigBackupsTable); err != nil {
		return fmt.Errorf("failed to create config_backups table: %w", err)
	}

	// Create audit_log table with JSONB for flexible logging
	createAuditLogTable := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		user_name VARCHAR(100) NOT NULL,
		action VARCHAR(50) NOT NULL,
		resource_type VARCHAR(50),
		resource_id VARCHAR(100),
		details JSONB,
		ip_address INET,
		session_id UUID,
		success BOOLEAN DEFAULT TRUE
	);`

	if _, err := pdb.DB.Exec(createAuditLogTable); err != nil {
		return fmt.Errorf("failed to create audit_log table: %w", err)
	}

	// Create distributed_locks table for multi-instance coordination
	createLocksTable := `
	CREATE TABLE IF NOT EXISTS distributed_locks (
		id SERIAL PRIMARY KEY,
		lock_name VARCHAR(255) UNIQUE NOT NULL,
		instance_id UUID NOT NULL,
		acquired_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMPTZ NOT NULL,
		metadata JSONB
	);`

	if _, err := pdb.DB.Exec(createLocksTable); err != nil {
		return fmt.Errorf("failed to create distributed_locks table: %w", err)
	}

	// Create indices for better performance
	indices := []string{
		"CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);",
		"CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site_name);",
		"CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);",
		"CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);",
		"CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices USING GIST(ip_address inet_ops);",
		"CREATE INDEX IF NOT EXISTS idx_devices_tags ON devices USING GIN(tags);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_device ON task_history(device_id);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_user ON task_history(executed_by);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_task_id ON task_history(task_id);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_execution_time ON task_history(execution_time);",
		"CREATE INDEX IF NOT EXISTS idx_task_history_metadata ON task_history USING GIN(metadata);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_name);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);",
		"CREATE INDEX IF NOT EXISTS idx_audit_log_details ON audit_log USING GIN(details);",
		"CREATE INDEX IF NOT EXISTS idx_config_backups_device ON config_backups(device_id);",
		"CREATE INDEX IF NOT EXISTS idx_config_backups_time ON config_backups(backup_time);",
		"CREATE INDEX IF NOT EXISTS idx_distributed_locks_expires ON distributed_locks(expires_at);",
	}

	for _, index := range indices {
		if _, err := pdb.DB.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Create triggers for updated_at timestamps
	triggers := []string{
		`CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql';`,

		`DROP TRIGGER IF EXISTS update_devices_updated_at ON devices;
		CREATE TRIGGER update_devices_updated_at
			BEFORE UPDATE ON devices
			FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();`,

		`DROP TRIGGER IF EXISTS update_device_credentials_updated_at ON device_credentials;
		CREATE TRIGGER update_device_credentials_updated_at
			BEFORE UPDATE ON device_credentials
			FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();`,
	}

	for _, trigger := range triggers {
		if _, err := pdb.DB.Exec(trigger); err != nil {
			return fmt.Errorf("failed to create trigger: %w", err)
		}
	}

	pdb.logger.Info("PostgreSQL migrations completed successfully")
	return nil
}

// GetStats returns database statistics
func (pdb *PostgresDB) GetStats() sql.DBStats {
	return pdb.DB.Stats()
}

// Close closes the database connection
func (pdb *PostgresDB) Close() error {
	pdb.logger.Info("Closing PostgreSQL database connection")
	return pdb.DB.Close()
}

// AcquireDistributedLock attempts to acquire a distributed lock
func (pdb *PostgresDB) AcquireDistributedLock(ctx context.Context, lockName, instanceID string, ttl time.Duration) (bool, error) {
	expiresAt := time.Now().Add(ttl)

	query := `
		INSERT INTO distributed_locks (lock_name, instance_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (lock_name) DO UPDATE SET
			instance_id = $2,
			acquired_at = CURRENT_TIMESTAMP,
			expires_at = $3
		WHERE distributed_locks.expires_at < CURRENT_TIMESTAMP
		RETURNING id`

	var lockID int
	err := pdb.DB.GetContext(ctx, &lockID, query, lockName, instanceID, expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			// Lock is already held by another instance
			return false, nil
		}
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return true, nil
}

// ReleaseDistributedLock releases a distributed lock
func (pdb *PostgresDB) ReleaseDistributedLock(ctx context.Context, lockName, instanceID string) error {
	query := `DELETE FROM distributed_locks WHERE lock_name = $1 AND instance_id = $2`

	_, err := pdb.DB.ExecContext(ctx, query, lockName, instanceID)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

// CleanupExpiredLocks removes expired locks
func (pdb *PostgresDB) CleanupExpiredLocks(ctx context.Context) error {
	query := `DELETE FROM distributed_locks WHERE expires_at < CURRENT_TIMESTAMP`

	result, err := pdb.DB.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired locks: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		pdb.logger.Info("Cleaned up expired distributed locks", zap.Int64("count", affected))
	}

	return nil
}