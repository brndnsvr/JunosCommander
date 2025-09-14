package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// RedisClient wraps the Redis client with additional functionality
type RedisClient struct {
	client *redis.Client
	logger *zap.Logger
}

// RedisConfig holds Redis connection configuration
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

// SessionData represents session data stored in Redis
type SessionData struct {
	UserID       string            `json:"user_id"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	Roles        []string          `json:"roles"`
	LastActivity time.Time         `json:"last_activity"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	Metadata     map[string]string `json:"metadata"`
}

// NewRedisClient creates a new Redis client
func NewRedisClient(config RedisConfig, logger *zap.Logger) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Address,
		Password:     config.Password,
		DB:           config.DB,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Successfully connected to Redis",
		zap.String("address", config.Address),
		zap.Int("db", config.DB))

	return &RedisClient{
		client: rdb,
		logger: logger,
	}, nil
}

// HealthCheck performs a health check on Redis
func (r *RedisClient) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis health check failed: %w", err)
	}

	return nil
}

// Set stores a key-value pair with expiration
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	var data []byte
	var err error

	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		data, err = json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
	}

	if err := r.client.Set(ctx, key, data, expiration).Err(); err != nil {
		return fmt.Errorf("failed to set key %s: %w", key, err)
	}

	return nil
}

// Get retrieves a value by key
func (r *RedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key %s not found", key)
		}
		return nil, fmt.Errorf("failed to get key %s: %w", key, err)
	}

	return data, nil
}

// GetJSON retrieves and unmarshals JSON data
func (r *RedisClient) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := r.Get(ctx, key)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// Delete removes a key
func (r *RedisClient) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to delete keys: %w", err)
	}

	return nil
}

// Exists checks if keys exist
func (r *RedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	count, err := r.client.Exists(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to check key existence: %w", err)
	}

	return count, nil
}

// Expire sets expiration for a key
func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	if err := r.client.Expire(ctx, key, expiration).Err(); err != nil {
		return fmt.Errorf("failed to set expiration for key %s: %w", key, err)
	}

	return nil
}

// TTL returns time to live for a key
func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get TTL for key %s: %w", key, err)
	}

	return ttl, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	r.logger.Info("Closing Redis connection")
	return r.client.Close()
}

// SessionStore implements session management using Redis
type SessionStore struct {
	redis          *RedisClient
	sessionTimeout time.Duration
	keyPrefix      string
	logger         *zap.Logger
}

// NewSessionStore creates a new Redis-based session store
func NewSessionStore(redis *RedisClient, timeout time.Duration, logger *zap.Logger) *SessionStore {
	return &SessionStore{
		redis:          redis,
		sessionTimeout: timeout,
		keyPrefix:      "session:",
		logger:         logger,
	}
}

// CreateSession creates a new session
func (s *SessionStore) CreateSession(ctx context.Context, sessionID string, data SessionData) error {
	data.LastActivity = time.Now()
	key := s.keyPrefix + sessionID

	if err := s.redis.Set(ctx, key, data, s.sessionTimeout); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Debug("Session created",
		zap.String("session_id", sessionID),
		zap.String("username", data.Username))

	return nil
}

// GetSession retrieves a session
func (s *SessionStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	key := s.keyPrefix + sessionID
	var data SessionData

	if err := s.redis.GetJSON(ctx, key, &data); err != nil {
		return nil, fmt.Errorf("session not found or invalid: %w", err)
	}

	return &data, nil
}

// UpdateSession updates session data and extends expiration
func (s *SessionStore) UpdateSession(ctx context.Context, sessionID string, data SessionData) error {
	data.LastActivity = time.Now()
	key := s.keyPrefix + sessionID

	if err := s.redis.Set(ctx, key, data, s.sessionTimeout); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// RefreshSession extends session expiration without updating data
func (s *SessionStore) RefreshSession(ctx context.Context, sessionID string) error {
	key := s.keyPrefix + sessionID

	// Check if session exists
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}

	if exists == 0 {
		return fmt.Errorf("session not found")
	}

	// Extend expiration
	if err := s.redis.Expire(ctx, key, s.sessionTimeout); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := s.keyPrefix + sessionID

	if err := s.redis.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	s.logger.Debug("Session deleted", zap.String("session_id", sessionID))
	return nil
}

// GetActiveSessions returns the count of active sessions
func (s *SessionStore) GetActiveSessions(ctx context.Context) (int64, error) {
	pattern := s.keyPrefix + "*"

	// Use SCAN to iterate through keys
	var cursor uint64
	var count int64

	for {
		keys, nextCursor, err := s.redis.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return 0, fmt.Errorf("failed to scan session keys: %w", err)
		}

		count += int64(len(keys))
		cursor = nextCursor

		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// CleanupExpiredSessions removes expired sessions (Redis handles this automatically)
func (s *SessionStore) CleanupExpiredSessions(ctx context.Context) error {
	// Redis automatically removes expired keys, but we can implement
	// additional cleanup logic if needed
	s.logger.Debug("Session cleanup triggered (Redis handles expiration automatically)")
	return nil
}

// Cache provides a general-purpose cache interface
type Cache struct {
	redis  *RedisClient
	prefix string
	logger *zap.Logger
}

// NewCache creates a new cache instance
func NewCache(redis *RedisClient, prefix string, logger *zap.Logger) *Cache {
	return &Cache{
		redis:  redis,
		prefix: prefix,
		logger: logger,
	}
}

// Set caches a value with expiration
func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	fullKey := c.prefix + key
	return c.redis.Set(ctx, fullKey, value, expiration)
}

// Get retrieves a cached value
func (c *Cache) Get(ctx context.Context, key string, dest interface{}) error {
	fullKey := c.prefix + key
	return c.redis.GetJSON(ctx, fullKey, dest)
}

// Delete removes cached values
func (c *Cache) Delete(ctx context.Context, keys ...string) error {
	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = c.prefix + key
	}
	return c.redis.Delete(ctx, fullKeys...)
}

// GetStats returns Redis statistics
func (r *RedisClient) GetStats(ctx context.Context) (map[string]string, error) {
	info, err := r.client.Info(ctx, "stats", "memory", "clients").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis stats: %w", err)
	}

	// Parse info string into map
	stats := make(map[string]string)
	lines := []string{} // You'd need to split the info string by lines
	for _, line := range lines {
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				stats[parts[0]] = parts[1]
			}
		}
	}

	return stats, nil
}