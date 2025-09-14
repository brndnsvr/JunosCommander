-- PostgreSQL initialization script for JunosCommander
-- Optimized for network device management at scale

-- Create database if not exists
SELECT 'CREATE DATABASE junoscommander'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'junoscommander')\gexec

-- Connect to the database
\c junoscommander;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS junoscommander;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set default search path
SET search_path TO junoscommander, public;

-- Create custom types
CREATE TYPE device_status AS ENUM ('active', 'inactive', 'maintenance', 'error');
CREATE TYPE task_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE auth_provider AS ENUM ('local', 'ldap', 'ad', 'radius', 'tacacs');

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET NOT NULL,
    site VARCHAR(100),
    model VARCHAR(100),
    os_version VARCHAR(50),
    status device_status DEFAULT 'active',
    last_seen TIMESTAMPTZ,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

-- Create indexes for devices
CREATE INDEX idx_devices_hostname ON devices(hostname);
CREATE INDEX idx_devices_ip_address ON devices(ip_address);
CREATE INDEX idx_devices_site ON devices(site);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_tags ON devices USING GIN(tags);
CREATE INDEX idx_devices_metadata ON devices USING GIN(metadata);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    full_name VARCHAR(255),
    auth_provider auth_provider DEFAULT 'local',
    is_active BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    last_login TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    failed_login_count INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    preferences JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for users
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_active ON users(is_active);

-- Sessions table (for tracking active sessions)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for sessions
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Tasks table
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    device_ids UUID[] NOT NULL,
    command TEXT NOT NULL,
    status task_status DEFAULT 'pending',
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    output JSONB DEFAULT '{}'::jsonb,
    error TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for tasks
CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_scheduled_at ON tasks(scheduled_at);
CREATE INDEX idx_tasks_device_ids ON tasks USING GIN(device_ids);

-- Command templates table
CREATE TABLE IF NOT EXISTS command_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100),
    command TEXT NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    is_dangerous BOOLEAN DEFAULT false,
    requires_approval BOOLEAN DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for command templates
CREATE INDEX idx_command_templates_name ON command_templates(name);
CREATE INDEX idx_command_templates_category ON command_templates(category);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    username VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    request_data JSONB,
    response_data JSONB,
    status_code INTEGER,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
) PARTITION BY RANGE (created_at);

-- Create monthly partitions for audit logs
CREATE TABLE audit.logs_2024_01 PARTITION OF audit.logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE audit.logs_2024_02 PARTITION OF audit.logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
-- Add more partitions as needed

-- Create indexes for audit logs
CREATE INDEX idx_audit_logs_user_id ON audit.logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit.logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit.logs(created_at);

-- Device configurations backup table
CREATE TABLE IF NOT EXISTS device_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_type VARCHAR(50) DEFAULT 'running',
    config_data TEXT NOT NULL,
    hash VARCHAR(64) NOT NULL,
    backed_up_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for device configs
CREATE INDEX idx_device_configs_device_id ON device_configs(device_id);
CREATE INDEX idx_device_configs_created_at ON device_configs(created_at);
CREATE INDEX idx_device_configs_hash ON device_configs(hash);

-- Distributed locks table (for multi-instance coordination)
CREATE TABLE IF NOT EXISTS distributed_locks (
    lock_key VARCHAR(255) PRIMARY KEY,
    locked_by VARCHAR(255) NOT NULL,
    locked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Create index for distributed locks
CREATE INDEX idx_distributed_locks_expires_at ON distributed_locks(expires_at);

-- Create roles
CREATE ROLE junoscommander_app WITH LOGIN PASSWORD '${POSTGRES_PASSWORD}';
CREATE ROLE junoscommander_readonly WITH LOGIN PASSWORD '${POSTGRES_READONLY_PASSWORD}';
CREATE ROLE junoscommander_backup WITH LOGIN PASSWORD '${POSTGRES_BACKUP_PASSWORD}';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE junoscommander TO junoscommander_app;
GRANT CONNECT ON DATABASE junoscommander TO junoscommander_readonly;
GRANT CONNECT ON DATABASE junoscommander TO junoscommander_backup;

GRANT ALL ON SCHEMA junoscommander TO junoscommander_app;
GRANT USAGE ON SCHEMA junoscommander TO junoscommander_readonly;
GRANT USAGE ON SCHEMA junoscommander TO junoscommander_backup;

GRANT ALL ON ALL TABLES IN SCHEMA junoscommander TO junoscommander_app;
GRANT SELECT ON ALL TABLES IN SCHEMA junoscommander TO junoscommander_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA junoscommander TO junoscommander_backup;

GRANT ALL ON ALL SEQUENCES IN SCHEMA junoscommander TO junoscommander_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA junoscommander TO junoscommander_readonly;

-- Audit schema permissions
GRANT ALL ON SCHEMA audit TO junoscommander_app;
GRANT USAGE ON SCHEMA audit TO junoscommander_readonly;
GRANT ALL ON ALL TABLES IN SCHEMA audit TO junoscommander_app;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO junoscommander_readonly;

-- Create update trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update trigger to tables
CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_command_templates_updated_at BEFORE UPDATE ON command_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create cleanup function for expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create cleanup function for expired locks
CREATE OR REPLACE FUNCTION cleanup_expired_locks()
RETURNS void AS $$
BEGIN
    DELETE FROM distributed_locks WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Insert default data
INSERT INTO users (username, email, full_name, is_admin, auth_provider)
VALUES ('admin', 'admin@junoscommander.local', 'System Administrator', true, 'local')
ON CONFLICT (username) DO NOTHING;

-- Create statistics view
CREATE OR REPLACE VIEW device_statistics AS
SELECT
    COUNT(*) as total_devices,
    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_devices,
    COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive_devices,
    COUNT(CASE WHEN status = 'maintenance' THEN 1 END) as maintenance_devices,
    COUNT(CASE WHEN status = 'error' THEN 1 END) as error_devices,
    COUNT(DISTINCT site) as total_sites
FROM devices;

-- Create task statistics view
CREATE OR REPLACE VIEW task_statistics AS
SELECT
    COUNT(*) as total_tasks,
    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks,
    COUNT(CASE WHEN status = 'running' THEN 1 END) as running_tasks,
    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_tasks,
    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_tasks,
    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) as avg_task_duration_seconds
FROM tasks
WHERE completed_at IS NOT NULL;