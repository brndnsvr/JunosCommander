#!/usr/bin/env python3
"""
Database management utility for JunosCommander
"""

import sqlite3
import sys
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path

DEFAULT_DB_PATH = "../data/junoscommander.db"

def init_database(db_path):
    """Initialize the database with schema"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Read and execute schema from database.go migrations
    schema = """
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
    );

    CREATE TABLE IF NOT EXISTS device_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        credential_type VARCHAR(20),
        username VARCHAR(100),
        encrypted_password TEXT,
        ssh_key_path VARCHAR(255),
        enable_password TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id)
    );

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
    );
    """

    for statement in schema.split(';'):
        if statement.strip():
            cursor.execute(statement)

    conn.commit()
    conn.close()
    print(f"Database initialized at {db_path}")

def add_device(db_path, hostname, ip_address, site_name, device_type, **kwargs):
    """Add a new device to the database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO devices (hostname, ip_address, site_name, device_type,
                                device_sub_type, tags, model, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            hostname,
            ip_address,
            site_name,
            device_type,
            kwargs.get('device_sub_type', 'router'),
            kwargs.get('tags', ''),
            kwargs.get('model', ''),
            kwargs.get('status', 'active')
        ))
        conn.commit()
        print(f"Device {hostname} added successfully")
    except sqlite3.IntegrityError:
        print(f"Error: Device {hostname} already exists")
    finally:
        conn.close()

def list_devices(db_path):
    """List all devices in the database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, hostname, ip_address, site_name, device_type, status
        FROM devices
        ORDER BY hostname
    """)

    devices = cursor.fetchall()
    conn.close()

    if devices:
        print(f"{'ID':<5} {'Hostname':<30} {'IP Address':<15} {'Site':<15} {'Type':<15} {'Status':<10}")
        print("-" * 100)
        for device in devices:
            print(f"{device[0]:<5} {device[1]:<30} {device[2]:<15} {device[3]:<15} {device[4]:<15} {device[5]:<10}")
    else:
        print("No devices found")

def import_devices(db_path, file_path):
    """Import devices from CSV file"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        imported = 0
        skipped = 0

        for row in reader:
            try:
                cursor.execute("""
                    INSERT INTO devices (hostname, ip_address, site_name, device_type,
                                        device_sub_type, tags, model, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row['hostname'],
                    row['ip_address'],
                    row['site_name'],
                    row.get('device_type', 'junos'),
                    row.get('device_sub_type', 'router'),
                    row.get('tags', ''),
                    row.get('model', ''),
                    row.get('status', 'active')
                ))
                imported += 1
            except sqlite3.IntegrityError:
                skipped += 1
                print(f"Skipping duplicate: {row['hostname']}")

    conn.commit()
    conn.close()
    print(f"Imported {imported} devices, skipped {skipped} duplicates")

def delete_device(db_path, hostname):
    """Delete a device from the database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM devices WHERE hostname = ?", (hostname,))

    if cursor.rowcount > 0:
        conn.commit()
        print(f"Device {hostname} deleted successfully")
    else:
        print(f"Device {hostname} not found")

    conn.close()

def main():
    parser = argparse.ArgumentParser(description='JunosCommander Database Manager')
    parser.add_argument('--db', default=DEFAULT_DB_PATH, help='Database path')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Init command
    subparsers.add_parser('init', help='Initialize database')

    # Add command
    add_parser = subparsers.add_parser('add', help='Add a device')
    add_parser.add_argument('--hostname', required=True, help='Device hostname')
    add_parser.add_argument('--ip', required=True, help='IP address')
    add_parser.add_argument('--site', required=True, help='Site name')
    add_parser.add_argument('--type', default='junos', help='Device type')
    add_parser.add_argument('--subtype', default='router', help='Device sub-type')
    add_parser.add_argument('--tags', default='', help='Tags (comma-separated)')
    add_parser.add_argument('--model', default='', help='Device model')

    # List command
    subparsers.add_parser('list', help='List all devices')

    # Import command
    import_parser = subparsers.add_parser('import', help='Import devices from CSV')
    import_parser.add_argument('file', help='CSV file path')

    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a device')
    delete_parser.add_argument('hostname', help='Device hostname')

    args = parser.parse_args()

    # Ensure database directory exists
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    if args.command == 'init':
        init_database(args.db)
    elif args.command == 'add':
        add_device(args.db, args.hostname, args.ip, args.site, args.type,
                  device_sub_type=args.subtype, tags=args.tags, model=args.model)
    elif args.command == 'list':
        list_devices(args.db)
    elif args.command == 'import':
        import_devices(args.db, args.file)
    elif args.command == 'delete':
        delete_device(args.db, args.hostname)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()