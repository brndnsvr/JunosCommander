#!/usr/bin/env python3
"""
Database Health Check Script for JunosCommander
Monitors PostgreSQL and Redis health, performance metrics, and alerts on issues.

Usage:
    python db_health_check.py [--config /path/to/config.json]
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

import psycopg2
from psycopg2.extras import RealDictCursor
import redis
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class HealthCheckResult:
    """Health check result data structure"""
    service: str
    status: str  # healthy, warning, critical, unknown
    timestamp: datetime
    response_time_ms: float
    message: str
    metrics: Dict[str, Any]
    details: Dict[str, Any]


@dataclass
class ThresholdConfig:
    """Threshold configuration for health checks"""
    # PostgreSQL thresholds
    pg_connection_timeout: float = 5.0
    pg_query_timeout: float = 10.0
    pg_max_connections_warning: float = 0.8  # 80% of max_connections
    pg_max_connections_critical: float = 0.9  # 90% of max_connections
    pg_cache_hit_ratio_warning: float = 0.95  # 95%
    pg_cache_hit_ratio_critical: float = 0.90  # 90%
    pg_replication_lag_warning: int = 60  # seconds
    pg_replication_lag_critical: int = 300  # seconds

    # Redis thresholds
    redis_connection_timeout: float = 5.0
    redis_memory_usage_warning: float = 0.8  # 80% of maxmemory
    redis_memory_usage_critical: float = 0.9  # 90% of maxmemory
    redis_keyspace_hit_ratio_warning: float = 0.90  # 90%
    redis_keyspace_hit_ratio_critical: float = 0.80  # 80%


class DatabaseHealthChecker:
    """Database health monitoring for PostgreSQL and Redis"""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.thresholds = ThresholdConfig(**self.config.get('thresholds', {}))
        self.results: List[HealthCheckResult] = []

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or environment"""
        config = {
            'postgresql': {
                'host': os.getenv('DB_HOST', 'localhost'),
                'port': int(os.getenv('DB_PORT', '5432')),
                'database': os.getenv('DB_NAME', 'junoscommander'),
                'user': os.getenv('DB_USER', 'junoscommander_readonly'),
                'password': os.getenv('DB_PASSWORD', ''),
            },
            'redis': {
                'host': os.getenv('REDIS_HOST', 'localhost'),
                'port': int(os.getenv('REDIS_PORT', '6379')),
                'password': os.getenv('REDIS_PASSWORD', ''),
                'db': int(os.getenv('REDIS_DB', '0')),
            },
            'notifications': {
                'slack_webhook': os.getenv('SLACK_WEBHOOK_URL', ''),
                'email': os.getenv('NOTIFICATION_EMAIL', ''),
            },
            'thresholds': {}
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)

        return config

    def check_postgresql(self) -> HealthCheckResult:
        """Comprehensive PostgreSQL health check"""
        start_time = time.time()

        try:
            # Connect to PostgreSQL
            conn_params = self.config['postgresql'].copy()
            conn = psycopg2.connect(
                **conn_params,
                cursor_factory=RealDictCursor,
                connect_timeout=int(self.thresholds.pg_connection_timeout)
            )

            cursor = conn.cursor()

            # Basic connectivity test
            cursor.execute("SELECT 1")
            cursor.fetchone()

            # Collect comprehensive metrics
            metrics = {}
            details = {}

            # Database size and basic stats
            cursor.execute("""
                SELECT
                    pg_database_size(%s) as db_size_bytes,
                    (SELECT count(*) FROM devices) as device_count,
                    (SELECT count(*) FROM users) as user_count,
                    (SELECT count(*) FROM tasks WHERE created_at > NOW() - INTERVAL '24 hours') as recent_tasks
            """, (conn_params['database'],))

            db_stats = cursor.fetchone()
            metrics['database_size_mb'] = db_stats['db_size_bytes'] / (1024 * 1024)
            metrics['device_count'] = db_stats['device_count']
            metrics['user_count'] = db_stats['user_count']
            metrics['recent_tasks'] = db_stats['recent_tasks']

            # Connection stats
            cursor.execute("""
                SELECT
                    setting::int as max_connections,
                    count(*) as active_connections
                FROM pg_settings
                WHERE name = 'max_connections'
                CROSS JOIN pg_stat_activity
                WHERE state = 'active'
                GROUP BY setting
            """)

            conn_stats = cursor.fetchone()
            if conn_stats:
                metrics['max_connections'] = conn_stats['max_connections']
                metrics['active_connections'] = conn_stats['active_connections']
                metrics['connection_usage'] = conn_stats['active_connections'] / conn_stats['max_connections']

            # Cache hit ratio
            cursor.execute("""
                SELECT
                    sum(heap_blks_hit) / GREATEST(sum(heap_blks_hit + heap_blks_read), 1) as cache_hit_ratio
                FROM pg_statio_user_tables
            """)

            cache_stats = cursor.fetchone()
            if cache_stats and cache_stats['cache_hit_ratio']:
                metrics['cache_hit_ratio'] = float(cache_stats['cache_hit_ratio'])

            # Long running queries
            cursor.execute("""
                SELECT
                    count(*) as long_queries,
                    coalesce(max(extract(epoch from now() - query_start)), 0) as longest_query_seconds
                FROM pg_stat_activity
                WHERE state = 'active'
                AND query_start < NOW() - INTERVAL '1 minute'
                AND query NOT LIKE '%pg_stat_activity%'
            """)

            query_stats = cursor.fetchone()
            metrics['long_running_queries'] = query_stats['long_queries']
            metrics['longest_query_seconds'] = float(query_stats['longest_query_seconds'])

            # Table statistics for key tables
            cursor.execute("""
                SELECT
                    schemaname,
                    tablename,
                    n_tup_ins + n_tup_upd + n_tup_del as total_modifications,
                    n_dead_tup,
                    last_vacuum,
                    last_analyze
                FROM pg_stat_user_tables
                WHERE tablename IN ('devices', 'tasks', 'users', 'task_results')
                ORDER BY n_dead_tup DESC
            """)

            table_stats = cursor.fetchall()
            details['table_statistics'] = [dict(row) for row in table_stats]

            # Replication lag (if replica exists)
            try:
                cursor.execute("""
                    SELECT
                        pg_last_wal_receive_lsn() != pg_last_wal_replay_lsn() as is_replica,
                        COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())), 0) as lag_seconds
                """)

                repl_stats = cursor.fetchone()
                if repl_stats and repl_stats['is_replica']:
                    metrics['replication_lag_seconds'] = float(repl_stats['lag_seconds'])
            except psycopg2.Error:
                # Not a replica or replication not configured
                pass

            # Locks
            cursor.execute("""
                SELECT mode, count(*) as count
                FROM pg_locks l
                JOIN pg_stat_activity a ON l.pid = a.pid
                WHERE a.state = 'active'
                GROUP BY mode
            """)

            lock_stats = cursor.fetchall()
            details['active_locks'] = {row['mode']: row['count'] for row in lock_stats}

            response_time_ms = (time.time() - start_time) * 1000

            # Determine health status
            status = 'healthy'
            messages = []

            # Check connection usage
            if 'connection_usage' in metrics:
                if metrics['connection_usage'] >= self.thresholds.pg_max_connections_critical:
                    status = 'critical'
                    messages.append(f"Connection usage critical: {metrics['connection_usage']:.1%}")
                elif metrics['connection_usage'] >= self.thresholds.pg_max_connections_warning:
                    if status == 'healthy':
                        status = 'warning'
                    messages.append(f"Connection usage high: {metrics['connection_usage']:.1%}")

            # Check cache hit ratio
            if 'cache_hit_ratio' in metrics:
                if metrics['cache_hit_ratio'] < self.thresholds.pg_cache_hit_ratio_critical:
                    status = 'critical'
                    messages.append(f"Cache hit ratio critical: {metrics['cache_hit_ratio']:.1%}")
                elif metrics['cache_hit_ratio'] < self.thresholds.pg_cache_hit_ratio_warning:
                    if status == 'healthy':
                        status = 'warning'
                    messages.append(f"Cache hit ratio low: {metrics['cache_hit_ratio']:.1%}")

            # Check replication lag
            if 'replication_lag_seconds' in metrics:
                if metrics['replication_lag_seconds'] > self.thresholds.pg_replication_lag_critical:
                    status = 'critical'
                    messages.append(f"Replication lag critical: {metrics['replication_lag_seconds']:.1f}s")
                elif metrics['replication_lag_seconds'] > self.thresholds.pg_replication_lag_warning:
                    if status == 'healthy':
                        status = 'warning'
                    messages.append(f"Replication lag high: {metrics['replication_lag_seconds']:.1f}s")

            # Check long running queries
            if metrics['long_running_queries'] > 5:
                if status == 'healthy':
                    status = 'warning'
                messages.append(f"Long running queries: {metrics['long_running_queries']}")

            message = '; '.join(messages) if messages else 'PostgreSQL is healthy'

            conn.close()

            return HealthCheckResult(
                service='postgresql',
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time_ms,
                message=message,
                metrics=metrics,
                details=details
            )

        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(f"PostgreSQL health check failed: {e}")

            return HealthCheckResult(
                service='postgresql',
                status='critical',
                timestamp=datetime.now(),
                response_time_ms=response_time_ms,
                message=f"PostgreSQL check failed: {str(e)}",
                metrics={},
                details={'error': str(e)}
            )

    def check_redis(self) -> HealthCheckResult:
        """Comprehensive Redis health check"""
        start_time = time.time()

        try:
            # Connect to Redis
            redis_config = self.config['redis'].copy()
            r = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                password=redis_config['password'] if redis_config['password'] else None,
                db=redis_config['db'],
                socket_timeout=self.thresholds.redis_connection_timeout,
                socket_connect_timeout=self.thresholds.redis_connection_timeout
            )

            # Basic connectivity test
            r.ping()

            # Collect metrics
            info = r.info()
            metrics = {}
            details = {}

            # Memory metrics
            metrics['used_memory_mb'] = info['used_memory'] / (1024 * 1024)
            metrics['used_memory_peak_mb'] = info['used_memory_peak'] / (1024 * 1024)

            if 'maxmemory' in info and info['maxmemory'] > 0:
                metrics['max_memory_mb'] = info['maxmemory'] / (1024 * 1024)
                metrics['memory_usage'] = info['used_memory'] / info['maxmemory']
            else:
                metrics['memory_usage'] = 0.0

            # Hit ratio
            keyspace_hits = info.get('keyspace_hits', 0)
            keyspace_misses = info.get('keyspace_misses', 0)
            total_requests = keyspace_hits + keyspace_misses

            if total_requests > 0:
                metrics['hit_ratio'] = keyspace_hits / total_requests
            else:
                metrics['hit_ratio'] = 1.0

            metrics['keyspace_hits'] = keyspace_hits
            metrics['keyspace_misses'] = keyspace_misses

            # Connection metrics
            metrics['connected_clients'] = info['connected_clients']
            metrics['blocked_clients'] = info.get('blocked_clients', 0)
            metrics['total_connections_received'] = info.get('total_connections_received', 0)

            # Performance metrics
            metrics['instantaneous_ops_per_sec'] = info.get('instantaneous_ops_per_sec', 0)
            metrics['total_commands_processed'] = info.get('total_commands_processed', 0)

            # Database metrics
            db_info = {}
            for key, value in info.items():
                if key.startswith('db'):
                    db_info[key] = value
            details['databases'] = db_info

            # Replication metrics (if applicable)
            if info.get('role') == 'master':
                metrics['connected_slaves'] = info.get('connected_slaves', 0)
            elif info.get('role') == 'slave':
                metrics['master_link_status'] = info.get('master_link_status', 'down')
                metrics['master_last_io_seconds_ago'] = info.get('master_last_io_seconds_ago', 0)

            # Memory fragmentation
            if 'mem_fragmentation_ratio' in info:
                metrics['memory_fragmentation_ratio'] = info['mem_fragmentation_ratio']

            response_time_ms = (time.time() - start_time) * 1000

            # Determine health status
            status = 'healthy'
            messages = []

            # Check memory usage
            if metrics['memory_usage'] >= self.thresholds.redis_memory_usage_critical:
                status = 'critical'
                messages.append(f"Memory usage critical: {metrics['memory_usage']:.1%}")
            elif metrics['memory_usage'] >= self.thresholds.redis_memory_usage_warning:
                if status == 'healthy':
                    status = 'warning'
                messages.append(f"Memory usage high: {metrics['memory_usage']:.1%}")

            # Check hit ratio
            if metrics['hit_ratio'] < self.thresholds.redis_keyspace_hit_ratio_critical:
                status = 'critical'
                messages.append(f"Hit ratio critical: {metrics['hit_ratio']:.1%}")
            elif metrics['hit_ratio'] < self.thresholds.redis_keyspace_hit_ratio_warning:
                if status == 'healthy':
                    status = 'warning'
                messages.append(f"Hit ratio low: {metrics['hit_ratio']:.1%}")

            # Check replication (if slave)
            if info.get('role') == 'slave':
                if metrics.get('master_link_status') == 'down':
                    status = 'critical'
                    messages.append("Master link is down")
                elif metrics.get('master_last_io_seconds_ago', 0) > 60:
                    if status == 'healthy':
                        status = 'warning'
                    messages.append(f"Master last IO: {metrics['master_last_io_seconds_ago']}s ago")

            message = '; '.join(messages) if messages else 'Redis is healthy'

            return HealthCheckResult(
                service='redis',
                status=status,
                timestamp=datetime.now(),
                response_time_ms=response_time_ms,
                message=message,
                metrics=metrics,
                details=details
            )

        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Redis health check failed: {e}")

            return HealthCheckResult(
                service='redis',
                status='critical',
                timestamp=datetime.now(),
                response_time_ms=response_time_ms,
                message=f"Redis check failed: {str(e)}",
                metrics={},
                details={'error': str(e)}
            )

    def send_notification(self, results: List[HealthCheckResult]):
        """Send notifications for critical issues"""
        critical_results = [r for r in results if r.status == 'critical']
        warning_results = [r for r in results if r.status == 'warning']

        if not critical_results and not warning_results:
            return

        # Prepare notification message
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message_lines = [f"JunosCommander Database Health Alert - {timestamp}"]

        if critical_results:
            message_lines.append("\n🔴 CRITICAL ISSUES:")
            for result in critical_results:
                message_lines.append(f"  • {result.service}: {result.message}")

        if warning_results:
            message_lines.append("\n⚠️  WARNINGS:")
            for result in warning_results:
                message_lines.append(f"  • {result.service}: {result.message}")

        message = '\n'.join(message_lines)

        # Send Slack notification
        slack_webhook = self.config['notifications']['slack_webhook']
        if slack_webhook:
            try:
                color = 'danger' if critical_results else 'warning'
                payload = {
                    'attachments': [{
                        'color': color,
                        'text': message,
                        'mrkdwn_in': ['text']
                    }]
                }

                response = requests.post(slack_webhook, json=payload, timeout=10)
                response.raise_for_status()
                logger.info("Slack notification sent successfully")
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")

        # Log the alert
        logger.warning(message)

    def run_health_checks(self) -> List[HealthCheckResult]:
        """Run all health checks and return results"""
        logger.info("Starting database health checks...")

        # Run PostgreSQL check
        pg_result = self.check_postgresql()
        self.results.append(pg_result)

        logger.info(f"PostgreSQL: {pg_result.status} - {pg_result.message}")

        # Run Redis check
        redis_result = self.check_redis()
        self.results.append(redis_result)

        logger.info(f"Redis: {redis_result.status} - {redis_result.message}")

        # Send notifications for issues
        self.send_notification(self.results)

        return self.results

    def generate_report(self, results: List[HealthCheckResult], output_file: Optional[str] = None) -> str:
        """Generate a detailed health check report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        report_lines = [
            "JunosCommander Database Health Check Report",
            "=" * 50,
            f"Generated: {timestamp}",
            ""
        ]

        for result in results:
            report_lines.extend([
                f"{result.service.upper()} Health Check",
                "-" * 30,
                f"Status: {result.status.upper()}",
                f"Response Time: {result.response_time_ms:.2f}ms",
                f"Message: {result.message}",
                ""
            ])

            if result.metrics:
                report_lines.append("Metrics:")
                for key, value in result.metrics.items():
                    if isinstance(value, float):
                        report_lines.append(f"  {key}: {value:.2f}")
                    else:
                        report_lines.append(f"  {key}: {value}")
                report_lines.append("")

            if result.details:
                report_lines.append("Details:")
                report_lines.append(json.dumps(result.details, indent=2, default=str))
                report_lines.append("")

        report = '\n'.join(report_lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Health check report saved to: {output_file}")

        return report


def main():
    parser = argparse.ArgumentParser(description='JunosCommander Database Health Check')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--output', help='Output file for health report')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--quiet', action='store_true', help='Suppress non-error output')

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    # Initialize health checker
    checker = DatabaseHealthChecker(args.config)

    # Run health checks
    results = checker.run_health_checks()

    # Output results
    if args.json:
        # JSON output
        json_results = [asdict(result) for result in results]
        # Convert datetime to string for JSON serialization
        for result in json_results:
            result['timestamp'] = result['timestamp'].isoformat()

        output = json.dumps(json_results, indent=2, default=str)
        print(output)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
    else:
        # Text report
        report = checker.generate_report(results, args.output)
        if not args.quiet:
            print(report)

    # Exit with appropriate code
    critical_count = len([r for r in results if r.status == 'critical'])
    if critical_count > 0:
        sys.exit(1)  # Critical issues found
    else:
        sys.exit(0)  # All good or only warnings


if __name__ == '__main__':
    main()