package lock

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DistributedLock represents a distributed lock
type DistributedLock interface {
	Acquire(ctx context.Context, lockName string, ttl time.Duration) (*Lock, error)
	Release(ctx context.Context, lock *Lock) error
	Renew(ctx context.Context, lock *Lock, ttl time.Duration) error
	IsHeld(ctx context.Context, lockName string) (bool, error)
}

// Lock represents an acquired lock
type Lock struct {
	Name       string    `json:"name"`
	InstanceID string    `json:"instance_id"`
	Token      string    `json:"token"`
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DatabaseLockProvider implements distributed locking using database
type DatabaseLockProvider struct {
	db         DatabaseLockInterface
	instanceID string
	logger     *zap.Logger
}

// DatabaseLockInterface defines the database operations needed for locking
type DatabaseLockInterface interface {
	AcquireDistributedLock(ctx context.Context, lockName, instanceID string, ttl time.Duration) (bool, error)
	ReleaseDistributedLock(ctx context.Context, lockName, instanceID string) error
	CleanupExpiredLocks(ctx context.Context) error
}

// NewDatabaseLockProvider creates a new database-based lock provider
func NewDatabaseLockProvider(db DatabaseLockInterface, instanceID string, logger *zap.Logger) *DatabaseLockProvider {
	return &DatabaseLockProvider{
		db:         db,
		instanceID: instanceID,
		logger:     logger,
	}
}

// Acquire attempts to acquire a distributed lock
func (dlp *DatabaseLockProvider) Acquire(ctx context.Context, lockName string, ttl time.Duration) (*Lock, error) {
	token := uuid.New().String()
	acquired, err := dlp.db.AcquireDistributedLock(ctx, lockName, dlp.instanceID, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		return nil, fmt.Errorf("lock %s is already held by another instance", lockName)
	}

	lock := &Lock{
		Name:       lockName,
		InstanceID: dlp.instanceID,
		Token:      token,
		AcquiredAt: time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}

	dlp.logger.Info("Lock acquired",
		zap.String("lock_name", lockName),
		zap.String("instance_id", dlp.instanceID),
		zap.Duration("ttl", ttl))

	return lock, nil
}

// Release releases a distributed lock
func (dlp *DatabaseLockProvider) Release(ctx context.Context, lock *Lock) error {
	if lock.InstanceID != dlp.instanceID {
		return fmt.Errorf("cannot release lock held by different instance")
	}

	err := dlp.db.ReleaseDistributedLock(ctx, lock.Name, dlp.instanceID)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	dlp.logger.Info("Lock released",
		zap.String("lock_name", lock.Name),
		zap.String("instance_id", dlp.instanceID))

	return nil
}

// Renew extends the TTL of a lock
func (dlp *DatabaseLockProvider) Renew(ctx context.Context, lock *Lock, ttl time.Duration) error {
	if lock.InstanceID != dlp.instanceID {
		return fmt.Errorf("cannot renew lock held by different instance")
	}

	// Re-acquire the lock with new TTL
	acquired, err := dlp.db.AcquireDistributedLock(ctx, lock.Name, dlp.instanceID, ttl)
	if err != nil {
		return fmt.Errorf("failed to renew lock: %w", err)
	}

	if !acquired {
		return fmt.Errorf("failed to renew lock: lock lost")
	}

	lock.ExpiresAt = time.Now().Add(ttl)
	dlp.logger.Debug("Lock renewed",
		zap.String("lock_name", lock.Name),
		zap.Duration("ttl", ttl))

	return nil
}

// IsHeld checks if a lock is currently held (by any instance)
func (dlp *DatabaseLockProvider) IsHeld(ctx context.Context, lockName string) (bool, error) {
	// Try to acquire the lock with minimal TTL - if it fails, it's held
	acquired, err := dlp.db.AcquireDistributedLock(ctx, lockName, "check-"+uuid.New().String(), 1*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to check lock status: %w", err)
	}

	if acquired {
		// We got the lock, so it wasn't held - release it immediately
		_ = dlp.db.ReleaseDistributedLock(ctx, lockName, "check-"+uuid.New().String())
		return false, nil
	}

	return true, nil
}

// RedisLockProvider implements distributed locking using Redis
type RedisLockProvider struct {
	redis      RedisLockInterface
	instanceID string
	logger     *zap.Logger
}

// RedisLockInterface defines the Redis operations needed for locking
type RedisLockInterface interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error)
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error)
	Expire(ctx context.Context, key string, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
}

// NewRedisLockProvider creates a new Redis-based lock provider
func NewRedisLockProvider(redis RedisLockInterface, instanceID string, logger *zap.Logger) *RedisLockProvider {
	return &RedisLockProvider{
		redis:      redis,
		instanceID: instanceID,
		logger:     logger,
	}
}

// Acquire attempts to acquire a distributed lock using Redis
func (rlp *RedisLockProvider) Acquire(ctx context.Context, lockName string, ttl time.Duration) (*Lock, error) {
	token := uuid.New().String()
	key := "lock:" + lockName
	value := fmt.Sprintf("%s:%s", rlp.instanceID, token)

	acquired, err := rlp.redis.SetNX(ctx, key, value, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire Redis lock: %w", err)
	}

	if !acquired {
		return nil, fmt.Errorf("lock %s is already held by another instance", lockName)
	}

	lock := &Lock{
		Name:       lockName,
		InstanceID: rlp.instanceID,
		Token:      token,
		AcquiredAt: time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}

	rlp.logger.Info("Redis lock acquired",
		zap.String("lock_name", lockName),
		zap.String("instance_id", rlp.instanceID),
		zap.Duration("ttl", ttl))

	return lock, nil
}

// Release releases a Redis-based distributed lock
func (rlp *RedisLockProvider) Release(ctx context.Context, lock *Lock) error {
	if lock.InstanceID != rlp.instanceID {
		return fmt.Errorf("cannot release lock held by different instance")
	}

	key := "lock:" + lock.Name
	value := fmt.Sprintf("%s:%s", rlp.instanceID, lock.Token)

	// Use Lua script to ensure atomic compare-and-delete
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`

	result, err := rlp.redis.Eval(ctx, script, []string{key}, value)
	if err != nil {
		return fmt.Errorf("failed to release Redis lock: %w", err)
	}

	if result.(int64) == 0 {
		return fmt.Errorf("lock was not held by this instance or has expired")
	}

	rlp.logger.Info("Redis lock released",
		zap.String("lock_name", lock.Name),
		zap.String("instance_id", rlp.instanceID))

	return nil
}

// Renew extends the TTL of a Redis lock
func (rlp *RedisLockProvider) Renew(ctx context.Context, lock *Lock, ttl time.Duration) error {
	if lock.InstanceID != rlp.instanceID {
		return fmt.Errorf("cannot renew lock held by different instance")
	}

	key := "lock:" + lock.Name
	value := fmt.Sprintf("%s:%s", rlp.instanceID, lock.Token)

	// Use Lua script to ensure atomic compare-and-renew
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("EXPIRE", KEYS[1], ARGV[2])
		else
			return 0
		end
	`

	result, err := rlp.redis.Eval(ctx, script, []string{key}, value, int(ttl.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to renew Redis lock: %w", err)
	}

	if result.(int64) == 0 {
		return fmt.Errorf("lock was not held by this instance or has expired")
	}

	lock.ExpiresAt = time.Now().Add(ttl)
	rlp.logger.Debug("Redis lock renewed",
		zap.String("lock_name", lock.Name),
		zap.Duration("ttl", ttl))

	return nil
}

// IsHeld checks if a Redis lock is currently held
func (rlp *RedisLockProvider) IsHeld(ctx context.Context, lockName string) (bool, error) {
	key := "lock:" + lockName
	_, err := rlp.redis.Get(ctx, key)
	if err != nil {
		// Assuming Get returns an error when key doesn't exist
		return false, nil
	}
	return true, nil
}

// LockManager provides high-level lock management functionality
type LockManager struct {
	provider DistributedLock
	locks    map[string]*Lock
	logger   *zap.Logger
}

// NewLockManager creates a new lock manager
func NewLockManager(provider DistributedLock, logger *zap.Logger) *LockManager {
	return &LockManager{
		provider: provider,
		locks:    make(map[string]*Lock),
		logger:   logger,
	}
}

// AcquireWithRetry attempts to acquire a lock with retry logic
func (lm *LockManager) AcquireWithRetry(ctx context.Context, lockName string, ttl time.Duration, maxRetries int, retryDelay time.Duration) (*Lock, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		lock, err := lm.provider.Acquire(ctx, lockName, ttl)
		if err == nil {
			lm.locks[lockName] = lock
			return lock, nil
		}

		lastErr = err
		lm.logger.Debug("Lock acquisition failed, retrying",
			zap.String("lock_name", lockName),
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", maxRetries),
			zap.Error(err))

		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed to acquire lock after %d attempts: %w", maxRetries+1, lastErr)
}

// ReleaseAll releases all locks held by this manager
func (lm *LockManager) ReleaseAll(ctx context.Context) error {
	var errors []error

	for lockName, lock := range lm.locks {
		if err := lm.provider.Release(ctx, lock); err != nil {
			errors = append(errors, fmt.Errorf("failed to release lock %s: %w", lockName, err))
		} else {
			delete(lm.locks, lockName)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to release some locks: %v", errors)
	}

	return nil
}

// StartRenewalProcess starts automatic lock renewal in the background
func (lm *LockManager) StartRenewalProcess(ctx context.Context, renewalInterval time.Duration) {
	ticker := time.NewTicker(renewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			lm.logger.Info("Stopping lock renewal process")
			return
		case <-ticker.C:
			lm.renewLocks(ctx)
		}
	}
}

// renewLocks renews all held locks
func (lm *LockManager) renewLocks(ctx context.Context) {
	for lockName, lock := range lm.locks {
		// Renew for original TTL duration
		ttl := lock.ExpiresAt.Sub(lock.AcquiredAt)
		if err := lm.provider.Renew(ctx, lock, ttl); err != nil {
			lm.logger.Error("Failed to renew lock",
				zap.String("lock_name", lockName),
				zap.Error(err))
			// Remove the lock from our tracking as we've lost it
			delete(lm.locks, lockName)
		}
	}
}

// WithLock executes a function while holding a lock
func (lm *LockManager) WithLock(ctx context.Context, lockName string, ttl time.Duration, fn func() error) error {
	lock, err := lm.provider.Acquire(ctx, lockName, ttl)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	defer func() {
		if releaseErr := lm.provider.Release(ctx, lock); releaseErr != nil {
			lm.logger.Error("Failed to release lock",
				zap.String("lock_name", lockName),
				zap.Error(releaseErr))
		}
	}()

	return fn()
}