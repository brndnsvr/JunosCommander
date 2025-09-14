package database

import (
	"database/sql"
	"time"
)

// Device represents a network device
type Device struct {
	ID            int            `json:"id"`
	Hostname      string         `json:"hostname"`
	IPAddress     string         `json:"ip_address"`
	SiteName      string         `json:"site_name"`
	DeviceType    string         `json:"device_type"`
	DeviceSubType sql.NullString `json:"device_sub_type"`
	Tags          sql.NullString `json:"tags"`
	SWVersion     sql.NullString `json:"sw_version"`
	Model         sql.NullString `json:"model"`
	SerialNumber  sql.NullString `json:"serial_number"`
	LastSeen      sql.NullTime   `json:"last_seen"`
	LastBackup    sql.NullTime   `json:"last_backup"`
	Status        string         `json:"status"`
	Notes         sql.NullString `json:"notes"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// DeviceCredential represents device authentication credentials
type DeviceCredential struct {
	ID                int            `json:"id"`
	DeviceID          int            `json:"device_id"`
	CredentialType    sql.NullString `json:"credential_type"`
	Username          sql.NullString `json:"username"`
	EncryptedPassword sql.NullString `json:"-"`
	SSHKeyPath        sql.NullString `json:"ssh_key_path"`
	EnablePassword    sql.NullString `json:"-"`
}

// TaskHistory represents a task execution record
type TaskHistory struct {
	ID            int            `json:"id"`
	TaskID        string         `json:"task_id"`
	DeviceID      int            `json:"device_id"`
	TaskType      string         `json:"task_type"`
	TaskName      sql.NullString `json:"task_name"`
	ExecutedBy    string         `json:"executed_by"`
	ExecutionTime time.Time      `json:"execution_time"`
	Status        string         `json:"status"`
	Output        sql.NullString `json:"output"`
	ErrorMessage  sql.NullString `json:"error_message"`
}

// ConfigBackup represents a device configuration backup
type ConfigBackup struct {
	ID          int       `json:"id"`
	DeviceID    int       `json:"device_id"`
	ConfigType  string    `json:"config_type"`
	ConfigData  string    `json:"config_data"`
	BackupTime  time.Time `json:"backup_time"`
	BackedUpBy  string    `json:"backed_up_by"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           int            `json:"id"`
	Timestamp    time.Time      `json:"timestamp"`
	User         string         `json:"user"`
	Action       string         `json:"action"`
	ResourceType sql.NullString `json:"resource_type"`
	ResourceID   sql.NullString `json:"resource_id"`
	Details      sql.NullString `json:"details"`
	IPAddress    sql.NullString `json:"ip_address"`
	SessionID    sql.NullString `json:"session_id"`
	Success      bool           `json:"success"`
}