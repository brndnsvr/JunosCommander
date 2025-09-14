package device

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/junoscommander/junoscommander/internal/database"
	"go.uber.org/zap"
)

// Manager handles device operations
type Manager struct {
	db     *sql.DB
	logger *zap.Logger
}

// NewManager creates a new device manager
func NewManager(db *sql.DB, logger *zap.Logger) *Manager {
	return &Manager{
		db:     db,
		logger: logger,
	}
}

// ListDevices returns all devices with optional filtering
func (m *Manager) ListDevices(filters map[string]string) ([]*database.Device, error) {
	query := `SELECT id, hostname, ip_address, site_name, device_type, device_sub_type,
			  tags, sw_version, model, serial_number, last_seen, last_backup,
			  status, notes, created_at, updated_at
			  FROM devices WHERE 1=1`

	var args []interface{}
	var conditions []string

	// Build filter conditions
	if site, ok := filters["site"]; ok && site != "" {
		conditions = append(conditions, "site_name = ?")
		args = append(args, site)
	}

	if deviceType, ok := filters["type"]; ok && deviceType != "" {
		conditions = append(conditions, "device_type = ?")
		args = append(args, deviceType)
	}

	if status, ok := filters["status"]; ok && status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}

	if tag, ok := filters["tag"]; ok && tag != "" {
		conditions = append(conditions, "tags LIKE ?")
		args = append(args, "%"+tag+"%")
	}

	// Add conditions to query
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY hostname"

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []*database.Device
	for rows.Next() {
		device := &database.Device{}
		err := rows.Scan(
			&device.ID, &device.Hostname, &device.IPAddress, &device.SiteName,
			&device.DeviceType, &device.DeviceSubType, &device.Tags,
			&device.SWVersion, &device.Model, &device.SerialNumber,
			&device.LastSeen, &device.LastBackup, &device.Status,
			&device.Notes, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			m.logger.Error("Failed to scan device row", zap.Error(err))
			continue
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// GetDevice returns a device by ID
func (m *Manager) GetDevice(id int) (*database.Device, error) {
	query := `SELECT id, hostname, ip_address, site_name, device_type, device_sub_type,
			  tags, sw_version, model, serial_number, last_seen, last_backup,
			  status, notes, created_at, updated_at
			  FROM devices WHERE id = ?`

	device := &database.Device{}
	err := m.db.QueryRow(query, id).Scan(
		&device.ID, &device.Hostname, &device.IPAddress, &device.SiteName,
		&device.DeviceType, &device.DeviceSubType, &device.Tags,
		&device.SWVersion, &device.Model, &device.SerialNumber,
		&device.LastSeen, &device.LastBackup, &device.Status,
		&device.Notes, &device.CreatedAt, &device.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return device, nil
}

// GetDeviceByHostname returns a device by hostname
func (m *Manager) GetDeviceByHostname(hostname string) (*database.Device, error) {
	query := `SELECT id, hostname, ip_address, site_name, device_type, device_sub_type,
			  tags, sw_version, model, serial_number, last_seen, last_backup,
			  status, notes, created_at, updated_at
			  FROM devices WHERE hostname = ?`

	device := &database.Device{}
	err := m.db.QueryRow(query, hostname).Scan(
		&device.ID, &device.Hostname, &device.IPAddress, &device.SiteName,
		&device.DeviceType, &device.DeviceSubType, &device.Tags,
		&device.SWVersion, &device.Model, &device.SerialNumber,
		&device.LastSeen, &device.LastBackup, &device.Status,
		&device.Notes, &device.CreatedAt, &device.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return device, nil
}

// CreateDevice adds a new device
func (m *Manager) CreateDevice(device *database.Device) error {
	query := `INSERT INTO devices (hostname, ip_address, site_name, device_type,
			  device_sub_type, tags, sw_version, model, serial_number, status, notes)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		device.Hostname, device.IPAddress, device.SiteName, device.DeviceType,
		device.DeviceSubType, device.Tags, device.SWVersion, device.Model,
		device.SerialNumber, device.Status, device.Notes,
	)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return fmt.Errorf("device with hostname %s already exists", device.Hostname)
		}
		return fmt.Errorf("failed to create device: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert ID: %w", err)
	}

	device.ID = int(id)
	m.logger.Info("Device created",
		zap.Int("id", device.ID),
		zap.String("hostname", device.Hostname))

	return nil
}

// UpdateDevice updates an existing device
func (m *Manager) UpdateDevice(device *database.Device) error {
	query := `UPDATE devices SET
			  ip_address = ?, site_name = ?, device_type = ?, device_sub_type = ?,
			  tags = ?, sw_version = ?, model = ?, serial_number = ?,
			  status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
			  WHERE id = ?`

	_, err := m.db.Exec(query,
		device.IPAddress, device.SiteName, device.DeviceType, device.DeviceSubType,
		device.Tags, device.SWVersion, device.Model, device.SerialNumber,
		device.Status, device.Notes, device.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	m.logger.Info("Device updated",
		zap.Int("id", device.ID),
		zap.String("hostname", device.Hostname))

	return nil
}

// DeleteDevice removes a device
func (m *Manager) DeleteDevice(id int) error {
	// First delete related records
	queries := []string{
		"DELETE FROM device_credentials WHERE device_id = ?",
		"DELETE FROM task_history WHERE device_id = ?",
		"DELETE FROM config_backups WHERE device_id = ?",
		"DELETE FROM devices WHERE id = ?",
	}

	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	for _, query := range queries {
		if _, err := tx.Exec(query, id); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to delete device: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.logger.Info("Device deleted", zap.Int("id", id))
	return nil
}

// GetDevicesByIDs returns devices by their IDs
func (m *Manager) GetDevicesByIDs(ids []int) ([]*database.Device, error) {
	if len(ids) == 0 {
		return []*database.Device{}, nil
	}

	// Build placeholder string for IN clause
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`SELECT id, hostname, ip_address, site_name, device_type, device_sub_type,
			  tags, sw_version, model, serial_number, last_seen, last_backup,
			  status, notes, created_at, updated_at
			  FROM devices WHERE id IN (%s)`, strings.Join(placeholders, ","))

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []*database.Device
	for rows.Next() {
		device := &database.Device{}
		err := rows.Scan(
			&device.ID, &device.Hostname, &device.IPAddress, &device.SiteName,
			&device.DeviceType, &device.DeviceSubType, &device.Tags,
			&device.SWVersion, &device.Model, &device.SerialNumber,
			&device.LastSeen, &device.LastBackup, &device.Status,
			&device.Notes, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			m.logger.Error("Failed to scan device row", zap.Error(err))
			continue
		}
		devices = append(devices, device)
	}

	return devices, nil
}