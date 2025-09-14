#!/usr/bin/env python3
"""
SQLite to PostgreSQL Migration Script for JunosCommander

This script migrates data from the existing SQLite database to PostgreSQL
while preserving data integrity and relationships.

Requirements:
- psycopg2-binary
- sqlite3 (built-in)
- python-dotenv

Usage:
    python sqlite_to_postgres.py --sqlite-db /path/to/sqlite.db --postgres-url postgresql://user:pass@host:port/db
"""

import argparse
import logging
import sqlite3
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import uuid4

import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('migration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SQLiteToPostgreSQLMigrator:
    """Migrates JunosCommander data from SQLite to PostgreSQL"""

    def __init__(self, sqlite_path: str, postgres_url: str):
        self.sqlite_path = sqlite_path
        self.postgres_url = postgres_url
        self.sqlite_conn = None
        self.postgres_conn = None
        self.migration_stats = {
            'devices': 0,
            'users': 0,
            'tasks': 0,
            'task_results': 0,
            'config_changes': 0,
            'user_sessions': 0,
            'device_groups': 0,
            'system_config': 0
        }

    def connect_databases(self) -> bool:
        """Establish connections to both databases"""
        try:
            # Connect to SQLite
            self.sqlite_conn = sqlite3.connect(self.sqlite_path)
            self.sqlite_conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite database: {self.sqlite_path}")

            # Connect to PostgreSQL
            self.postgres_conn = psycopg2.connect(
                self.postgres_url,
                cursor_factory=RealDictCursor
            )
            self.postgres_conn.autocommit = False
            logger.info("Connected to PostgreSQL database")

            return True

        except sqlite3.Error as e:
            logger.error(f"SQLite connection error: {e}")
            return False
        except psycopg2.Error as e:
            logger.error(f"PostgreSQL connection error: {e}")
            return False

    def get_sqlite_tables(self) -> List[str]:
        """Get list of tables in SQLite database"""
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found SQLite tables: {tables}")
        return tables

    def migrate_devices(self):
        """Migrate devices table from SQLite to PostgreSQL"""
        logger.info("Migrating devices...")

        sqlite_cursor = self.sqlite_conn.cursor()
        postgres_cursor = self.postgres_conn.cursor()

        try:
            # Get SQLite devices structure
            sqlite_cursor.execute("PRAGMA table_info(devices)")
            sqlite_columns = [row[1] for row in sqlite_cursor.fetchall()]
            logger.info(f"SQLite devices columns: {sqlite_columns}")

            # Fetch all devices from SQLite
            sqlite_cursor.execute("SELECT * FROM devices")
            devices = sqlite_cursor.fetchall()

            # Prepare migration data
            migrated_devices = []
            for device in devices:
                device_dict = dict(device)

                # Generate UUID if not exists
                device_id = device_dict.get('id') or str(uuid4())
                if not self._is_valid_uuid(device_id):
                    device_id = str(uuid4())

                # Map SQLite columns to PostgreSQL schema
                migrated_device = {
                    'id': device_id,
                    'hostname': device_dict.get('hostname', ''),
                    'ip_address': device_dict.get('ip_address', '127.0.0.1'),
                    'device_type': device_dict.get('device_type', 'juniper'),
                    'model': device_dict.get('model'),
                    'os_version': device_dict.get('os_version'),
                    'site': device_dict.get('site', 'unknown'),
                    'rack_position': device_dict.get('rack_position'),
                    'serial_number': device_dict.get('serial_number'),
                    'management_ip': device_dict.get('management_ip'),
                    'status': device_dict.get('status', 'unknown'),
                    'last_seen': self._parse_datetime(device_dict.get('last_seen')),
                    'last_config_change': self._parse_datetime(device_dict.get('last_config_change')),
                    'created_at': self._parse_datetime(device_dict.get('created_at'), datetime.now()),
                    'updated_at': self._parse_datetime(device_dict.get('updated_at'), datetime.now()),
                    'created_by': device_dict.get('created_by', 'migration'),
                    'properties': device_dict.get('properties', '{}')
                }

                migrated_devices.append(migrated_device)

            # Insert into PostgreSQL
            if migrated_devices:
                insert_query = """
                    INSERT INTO devices (
                        id, hostname, ip_address, device_type, model, os_version,
                        site, rack_position, serial_number, management_ip, status,
                        last_seen, last_config_change, created_at, updated_at,
                        created_by, properties
                    ) VALUES (
                        %(id)s, %(hostname)s, %(ip_address)s, %(device_type)s,
                        %(model)s, %(os_version)s, %(site)s, %(rack_position)s,
                        %(serial_number)s, %(management_ip)s, %(status)s,
                        %(last_seen)s, %(last_config_change)s, %(created_at)s,
                        %(updated_at)s, %(created_by)s, %(properties)s
                    ) ON CONFLICT (hostname) DO UPDATE SET
                        ip_address = EXCLUDED.ip_address,
                        updated_at = EXCLUDED.updated_at
                """

                execute_batch(postgres_cursor, insert_query, migrated_devices, page_size=100)
                self.migration_stats['devices'] = len(migrated_devices)
                logger.info(f"Migrated {len(migrated_devices)} devices")

        except Exception as e:
            logger.error(f"Error migrating devices: {e}")
            raise

    def migrate_users(self):
        """Migrate users table from SQLite to PostgreSQL"""
        logger.info("Migrating users...")

        sqlite_cursor = self.sqlite_conn.cursor()
        postgres_cursor = self.postgres_conn.cursor()

        try:
            # Check if users table exists in SQLite
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
            if not sqlite_cursor.fetchone():
                logger.info("Users table not found in SQLite, creating default admin user")
                self._create_default_admin_user(postgres_cursor)
                return

            sqlite_cursor.execute("SELECT * FROM users")
            users = sqlite_cursor.fetchall()

            migrated_users = []
            for user in users:
                user_dict = dict(user)

                user_id = user_dict.get('id') or str(uuid4())
                if not self._is_valid_uuid(user_id):
                    user_id = str(uuid4())

                migrated_user = {
                    'id': user_id,
                    'username': user_dict.get('username', ''),
                    'display_name': user_dict.get('display_name'),
                    'email': user_dict.get('email'),
                    'domain': user_dict.get('domain'),
                    'distinguished_name': user_dict.get('distinguished_name'),
                    'groups': user_dict.get('groups', '{}'),
                    'role': user_dict.get('role', 'operator'),
                    'permissions': user_dict.get('permissions', '{}'),
                    'active': user_dict.get('active', True),
                    'last_login': self._parse_datetime(user_dict.get('last_login')),
                    'login_count': user_dict.get('login_count', 0),
                    'created_at': self._parse_datetime(user_dict.get('created_at'), datetime.now()),
                    'updated_at': self._parse_datetime(user_dict.get('updated_at'), datetime.now())
                }

                migrated_users.append(migrated_user)

            if migrated_users:
                insert_query = """
                    INSERT INTO users (
                        id, username, display_name, email, domain, distinguished_name,
                        groups, role, permissions, active, last_login, login_count,
                        created_at, updated_at
                    ) VALUES (
                        %(id)s, %(username)s, %(display_name)s, %(email)s, %(domain)s,
                        %(distinguished_name)s, %(groups)s, %(role)s, %(permissions)s,
                        %(active)s, %(last_login)s, %(login_count)s, %(created_at)s,
                        %(updated_at)s
                    ) ON CONFLICT (username) DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        email = EXCLUDED.email,
                        updated_at = EXCLUDED.updated_at
                """

                execute_batch(postgres_cursor, insert_query, migrated_users, page_size=100)
                self.migration_stats['users'] = len(migrated_users)
                logger.info(f"Migrated {len(migrated_users)} users")

        except Exception as e:
            logger.error(f"Error migrating users: {e}")
            raise

    def migrate_tasks(self):
        """Migrate tasks and task_results tables"""
        logger.info("Migrating tasks...")

        sqlite_cursor = self.sqlite_conn.cursor()
        postgres_cursor = self.postgres_conn.cursor()

        try:
            # Check if tasks table exists
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks';")
            if not sqlite_cursor.fetchone():
                logger.info("Tasks table not found in SQLite, skipping")
                return

            sqlite_cursor.execute("SELECT * FROM tasks")
            tasks = sqlite_cursor.fetchall()

            migrated_tasks = []
            for task in tasks:
                task_dict = dict(task)

                task_id = task_dict.get('id') or str(uuid4())
                if not self._is_valid_uuid(task_id):
                    task_id = str(uuid4())

                # Handle device_ids (convert to UUID array)
                device_ids = task_dict.get('device_ids', '[]')
                if isinstance(device_ids, str):
                    try:
                        import json
                        device_ids = json.loads(device_ids)
                    except:
                        device_ids = []

                migrated_task = {
                    'id': task_id,
                    'task_type': task_dict.get('task_type', 'command'),
                    'command': task_dict.get('command', ''),
                    'device_ids': device_ids,
                    'device_filter': task_dict.get('device_filter', '{}'),
                    'status': task_dict.get('status', 'pending'),
                    'progress_percent': task_dict.get('progress_percent', 0),
                    'results': task_dict.get('results', '{}'),
                    'error_message': task_dict.get('error_message'),
                    'created_at': self._parse_datetime(task_dict.get('created_at'), datetime.now()),
                    'started_at': self._parse_datetime(task_dict.get('started_at')),
                    'completed_at': self._parse_datetime(task_dict.get('completed_at')),
                    'created_by': self._get_default_user_id(postgres_cursor),
                    'execution_mode': task_dict.get('execution_mode', 'interactive')
                }

                migrated_tasks.append(migrated_task)

            if migrated_tasks:
                insert_query = """
                    INSERT INTO tasks (
                        id, task_type, command, device_ids, device_filter, status,
                        progress_percent, results, error_message, created_at,
                        started_at, completed_at, created_by, execution_mode
                    ) VALUES (
                        %(id)s, %(task_type)s, %(command)s, %(device_ids)s,
                        %(device_filter)s, %(status)s, %(progress_percent)s,
                        %(results)s, %(error_message)s, %(created_at)s,
                        %(started_at)s, %(completed_at)s, %(created_by)s,
                        %(execution_mode)s
                    ) ON CONFLICT (id) DO NOTHING
                """

                execute_batch(postgres_cursor, insert_query, migrated_tasks, page_size=100)
                self.migration_stats['tasks'] = len(migrated_tasks)
                logger.info(f"Migrated {len(migrated_tasks)} tasks")

        except Exception as e:
            logger.error(f"Error migrating tasks: {e}")
            raise

    def migrate_system_config(self):
        """Migrate system configuration"""
        logger.info("Migrating system configuration...")

        sqlite_cursor = self.sqlite_conn.cursor()
        postgres_cursor = self.postgres_conn.cursor()

        try:
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_config';")
            if not sqlite_cursor.fetchone():
                logger.info("System config table not found in SQLite, skipping")
                return

            sqlite_cursor.execute("SELECT * FROM system_config")
            configs = sqlite_cursor.fetchall()

            migrated_configs = []
            for config in configs:
                config_dict = dict(config)

                migrated_config = {
                    'key': config_dict.get('key', ''),
                    'value': config_dict.get('value', '{}'),
                    'description': config_dict.get('description'),
                    'category': config_dict.get('category', 'general'),
                    'updated_at': self._parse_datetime(config_dict.get('updated_at'), datetime.now()),
                    'updated_by': self._get_default_user_id(postgres_cursor)
                }

                migrated_configs.append(migrated_config)

            if migrated_configs:
                insert_query = """
                    INSERT INTO system_config (
                        key, value, description, category, updated_at, updated_by
                    ) VALUES (
                        %(key)s, %(value)s, %(description)s, %(category)s,
                        %(updated_at)s, %(updated_by)s
                    ) ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """

                execute_batch(postgres_cursor, insert_query, migrated_configs, page_size=100)
                self.migration_stats['system_config'] = len(migrated_configs)
                logger.info(f"Migrated {len(migrated_configs)} configuration items")

        except Exception as e:
            logger.error(f"Error migrating system config: {e}")
            raise

    def validate_migration(self) -> bool:
        """Validate the migration by comparing record counts"""
        logger.info("Validating migration...")

        try:
            sqlite_cursor = self.sqlite_conn.cursor()
            postgres_cursor = self.postgres_conn.cursor()

            validation_passed = True

            # Check devices count
            sqlite_cursor.execute("SELECT COUNT(*) FROM devices")
            sqlite_count = sqlite_cursor.fetchone()[0]
            postgres_cursor.execute("SELECT COUNT(*) FROM devices")
            postgres_count = postgres_cursor.fetchone()[0]

            if sqlite_count != postgres_count:
                logger.warning(f"Device count mismatch: SQLite={sqlite_count}, PostgreSQL={postgres_count}")
                validation_passed = False
            else:
                logger.info(f"Device count validation passed: {postgres_count}")

            # Validate data integrity with sample queries
            postgres_cursor.execute("SELECT COUNT(*) FROM devices WHERE hostname IS NOT NULL AND hostname != ''")
            valid_hostnames = postgres_cursor.fetchone()[0]
            logger.info(f"Devices with valid hostnames: {valid_hostnames}")

            postgres_cursor.execute("SELECT COUNT(*) FROM devices WHERE ip_address IS NOT NULL")
            valid_ips = postgres_cursor.fetchone()[0]
            logger.info(f"Devices with valid IP addresses: {valid_ips}")

            return validation_passed

        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False

    def _is_valid_uuid(self, uuid_string: str) -> bool:
        """Check if string is a valid UUID"""
        try:
            from uuid import UUID
            UUID(uuid_string)
            return True
        except (ValueError, TypeError):
            return False

    def _parse_datetime(self, dt_string: str, default=None):
        """Parse datetime string to datetime object"""
        if not dt_string:
            return default

        try:
            # Try common datetime formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f']:
                try:
                    return datetime.strptime(dt_string, fmt)
                except ValueError:
                    continue
            return default
        except Exception:
            return default

    def _get_default_user_id(self, postgres_cursor) -> str:
        """Get or create default user ID for migration"""
        postgres_cursor.execute("SELECT id FROM users WHERE username = 'admin' LIMIT 1")
        result = postgres_cursor.fetchone()
        if result:
            return result['id']

        # Create default admin user
        admin_id = str(uuid4())
        postgres_cursor.execute("""
            INSERT INTO users (id, username, display_name, email, role, active, created_at, updated_at)
            VALUES (%s, 'admin', 'Migration Admin', 'admin@migration.local', 'admin', true, %s, %s)
            ON CONFLICT (username) DO NOTHING
        """, (admin_id, datetime.now(), datetime.now()))

        return admin_id

    def _create_default_admin_user(self, postgres_cursor):
        """Create default admin user if no users exist"""
        admin_id = str(uuid4())
        postgres_cursor.execute("""
            INSERT INTO users (id, username, display_name, email, role, active, created_at, updated_at)
            VALUES (%s, 'admin', 'System Administrator', 'admin@junoscommander.local', 'admin', true, %s, %s)
            ON CONFLICT (username) DO NOTHING
        """, (admin_id, datetime.now(), datetime.now()))

        self.migration_stats['users'] = 1
        logger.info("Created default admin user")

    def run_migration(self) -> bool:
        """Run the complete migration process"""
        logger.info("Starting SQLite to PostgreSQL migration...")

        if not self.connect_databases():
            return False

        try:
            # Start transaction
            postgres_cursor = self.postgres_conn.cursor()
            postgres_cursor.execute("BEGIN")

            # Run migrations in order
            self.migrate_users()
            self.migrate_devices()
            self.migrate_tasks()
            self.migrate_system_config()

            # Commit transaction
            self.postgres_conn.commit()
            logger.info("Migration transaction committed")

            # Validate migration
            if not self.validate_migration():
                logger.warning("Migration validation failed, but data was still migrated")

            # Print migration statistics
            self._print_migration_stats()

            return True

        except Exception as e:
            logger.error(f"Migration failed: {e}")
            self.postgres_conn.rollback()
            logger.info("Migration transaction rolled back")
            return False

        finally:
            if self.sqlite_conn:
                self.sqlite_conn.close()
            if self.postgres_conn:
                self.postgres_conn.close()

    def _print_migration_stats(self):
        """Print migration statistics"""
        logger.info("Migration Statistics:")
        logger.info("-" * 40)
        for table, count in self.migration_stats.items():
            logger.info(f"{table:20}: {count:>8} records")
        logger.info("-" * 40)


def main():
    parser = argparse.ArgumentParser(description='Migrate JunosCommander from SQLite to PostgreSQL')
    parser.add_argument('--sqlite-db', required=True, help='Path to SQLite database file')
    parser.add_argument('--postgres-url', help='PostgreSQL connection URL (or use environment variables)')
    parser.add_argument('--dry-run', action='store_true', help='Validate connections without migrating')

    args = parser.parse_args()

    # Get PostgreSQL URL from arguments or environment
    postgres_url = args.postgres_url
    if not postgres_url:
        postgres_url = os.getenv('DATABASE_URL') or os.getenv('POSTGRES_URL')
        if not postgres_url:
            host = os.getenv('DB_HOST', 'localhost')
            port = os.getenv('DB_PORT', '5432')
            dbname = os.getenv('DB_NAME', 'junoscommander')
            user = os.getenv('DB_USER', 'junoscommander_app')
            password = os.getenv('DB_PASSWORD', '')
            postgres_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

    logger.info(f"SQLite database: {args.sqlite_db}")
    logger.info(f"PostgreSQL URL: {postgres_url.replace(postgres_url.split('@')[0].split(':')[-1], '***')}")

    migrator = SQLiteToPostgreSQLMigrator(args.sqlite_db, postgres_url)

    if args.dry_run:
        logger.info("Dry run mode - validating connections only")
        if migrator.connect_databases():
            logger.info("Connection validation successful")
            migrator.sqlite_conn.close()
            migrator.postgres_conn.close()
            return True
        else:
            logger.error("Connection validation failed")
            return False

    success = migrator.run_migration()

    if success:
        logger.info("Migration completed successfully!")
        sys.exit(0)
    else:
        logger.error("Migration failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()