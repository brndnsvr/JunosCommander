// Enhanced Session Management for Production Network Operations
// Includes hardware security, memory protection, and Junos-specific optimizations

package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

// SessionStore manages encrypted user sessions with hardware security features
type SessionStore struct {
	mu               sync.RWMutex
	sessions         map[string]*Session
	activeCount      int64
	cleanupTicker    *time.Ticker
	maxSessions      int64
	sessionTimeout   time.Duration
	hsm              HardwareSecurityModule
	memoryProtector  *MemoryProtector
	auditLogger      AuditLogger
}

// Session represents an encrypted user session with Junos-specific context
type Session struct {
	ID               string
	Username         string
	Groups           []string
	CreatedAt        time.Time
	LastActivity     time.Time
	ExpiresAt        time.Time
	AccessCount      int64
	DeviceContext    map[string]*DeviceSession
	EncryptedData    []byte
	SessionKey       []byte
	KeyDerivationSalt []byte
	AuthenticationMethod string
	IPAddress        string
	UserAgent        string
	mutex            sync.RWMutex
}

// DeviceSession tracks per-device session state for Junos optimization
type DeviceSession struct {
	DeviceID         int
	LastConnected    time.Time
	ConfigMode       bool
	PrivilegeLevel   int
	ActiveLocks      []string
	SessionState     map[string]interface{}
	CommandHistory   []CommandRecord
}

// CommandRecord tracks executed commands for audit and optimization
type CommandRecord struct {
	Command    string
	Timestamp  time.Time
	Duration   time.Duration
	Success    bool
	Output     string // Sanitized output for analysis
}

// Credentials represents encrypted user authentication data
type Credentials struct {
	Username      string              `json:"username"`
	Password      string              `json:"password"`
	Domain        string              `json:"domain"`
	Certificates  map[string][]byte   `json:"certificates,omitempty"`
	PrivateKeys   map[string][]byte   `json:"private_keys,omitempty"`
	Metadata      map[string]string   `json:"metadata"`
	ExpiresAt     time.Time           `json:"expires_at"`
	CreatedAt     time.Time           `json:"created_at"`
}

// HardwareSecurityModule interface for hardware-backed encryption
type HardwareSecurityModule interface {
	GenerateKey(keyType string, keySize int) ([]byte, error)
	Encrypt(data, key []byte) ([]byte, error)
	Decrypt(data, key []byte) ([]byte, error)
	SecureRandom(size int) ([]byte, error)
}

// MemoryProtector provides memory protection and secure cleanup
type MemoryProtector struct {
	allocations map[uintptr]int
	mu          sync.RWMutex
}

// AuditLogger interface for security audit logging
type AuditLogger interface {
	LogSessionEvent(event string, session *Session, metadata map[string]interface{})
	LogSecurityEvent(event string, severity string, details map[string]interface{})
}

// NewSessionStore creates a new session store with hardware security
func NewSessionStore(config SessionConfig) (*SessionStore, error) {
	hsm, err := NewHardwareSecurityModule(config.HSMConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HSM: %w", err)
	}

	memProtector := &MemoryProtector{
		allocations: make(map[uintptr]int),
	}

	store := &SessionStore{
		sessions:        make(map[string]*Session),
		cleanupTicker:   time.NewTicker(config.CleanupInterval),
		maxSessions:     config.MaxSessions,
		sessionTimeout:  config.SessionTimeout,
		hsm:             hsm,
		memoryProtector: memProtector,
		auditLogger:     config.AuditLogger,
	}

	// Start background cleanup routine
	go store.cleanupRoutine()

	// Start memory protection monitoring
	go store.memoryProtectionRoutine()

	return store, nil
}

// CreateSession creates a new encrypted session with hardware-backed security
func (s *SessionStore) CreateSession(ctx context.Context, username string, creds *Credentials) (*Session, error) {
	// Check session limits
	if atomic.LoadInt64(&s.activeCount) >= s.maxSessions {
		return nil, fmt.Errorf("maximum session limit reached")
	}

	// Generate cryptographically secure session ID
	sessionID, err := s.generateSecureSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create new session
	session := &Session{
		ID:                   sessionID,
		Username:             username,
		Groups:               creds.Metadata["groups"],
		CreatedAt:           time.Now(),
		LastActivity:        time.Now(),
		ExpiresAt:           time.Now().Add(s.sessionTimeout),
		DeviceContext:       make(map[string]*DeviceSession),
		AuthenticationMethod: creds.Metadata["auth_method"],
		IPAddress:           creds.Metadata["ip_address"],
		UserAgent:           creds.Metadata["user_agent"],
	}

	// Encrypt credentials with hardware security
	if err := s.encryptCredentials(session, creds); err != nil {
		return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Store session
	s.mu.Lock()
	s.sessions[sessionID] = session
	atomic.AddInt64(&s.activeCount, 1)
	s.mu.Unlock()

	// Audit log
	s.auditLogger.LogSessionEvent("session_created", session, map[string]interface{}{
		"ip_address": session.IPAddress,
		"user_agent": session.UserAgent,
	})

	return session, nil
}

// encryptCredentials encrypts credentials using hardware-backed encryption
func (s *SessionStore) encryptCredentials(session *Session, creds *Credentials) error {
	// Generate salt for key derivation
	salt, err := s.hsm.SecureRandom(32)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	session.KeyDerivationSalt = salt

	// Derive encryption key using Argon2id
	sessionKey := argon2.IDKey([]byte(session.ID), salt, 1, 64*1024, 4, 32)

	// Protect session key in memory
	s.protectMemoryRegion(unsafe.Pointer(&sessionKey[0]), len(sessionKey))
	session.SessionKey = sessionKey

	// Create GCM cipher
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce, err := s.hsm.SecureRandom(gcm.NonceSize())
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Marshal and encrypt credentials
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Encrypt with authenticated encryption
	ciphertext := gcm.Seal(nonce, nonce, plaintext, []byte(session.ID))
	session.EncryptedData = ciphertext

	// Securely clear plaintext from memory
	s.secureZero(plaintext)

	return nil
}

// DecryptCredentials decrypts and returns user credentials
func (s *SessionStore) DecryptCredentials(sessionID string) (*Credentials, error) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Check session expiry
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	// Update activity
	session.LastActivity = time.Now()
	atomic.AddInt64(&session.AccessCount, 1)

	// Decrypt credentials
	creds, err := s.decryptSessionCredentials(session)
	if err != nil {
		s.auditLogger.LogSecurityEvent("credential_decryption_failed", "high",
			map[string]interface{}{
				"session_id": sessionID,
				"username":   session.Username,
				"error":      err.Error(),
			})
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	return creds, nil
}

// decryptSessionCredentials performs the actual credential decryption
func (s *SessionStore) decryptSessionCredentials(session *Session) (*Credentials, error) {
	// Create cipher with session key
	block, err := aes.NewCipher(session.SessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(session.EncryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := session.EncryptedData[:nonceSize]
	ciphertext := session.EncryptedData[nonceSize:]

	// Decrypt with authentication verification
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(session.ID))
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	defer s.secureZero(plaintext)

	// Unmarshal credentials
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

// UpdateDeviceSession updates device-specific session state
func (s *SessionStore) UpdateDeviceSession(sessionID string, deviceID int, state *DeviceSession) error {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found")
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	deviceKey := fmt.Sprintf("device_%d", deviceID)
	session.DeviceContext[deviceKey] = state
	session.LastActivity = time.Now()

	return nil
}

// GetDeviceSession retrieves device-specific session state
func (s *SessionStore) GetDeviceSession(sessionID string, deviceID int) (*DeviceSession, error) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	session.mutex.RLock()
	defer session.mutex.RUnlock()

	deviceKey := fmt.Sprintf("device_%d", deviceID)
	if deviceSession, exists := session.DeviceContext[deviceKey]; exists {
		return deviceSession, nil
	}

	// Create new device session
	deviceSession := &DeviceSession{
		DeviceID:       deviceID,
		LastConnected:  time.Time{},
		ConfigMode:     false,
		PrivilegeLevel: 1,
		ActiveLocks:    make([]string, 0),
		SessionState:   make(map[string]interface{}),
		CommandHistory: make([]CommandRecord, 0),
	}

	return deviceSession, nil
}

// cleanupRoutine performs periodic session cleanup
func (s *SessionStore) cleanupRoutine() {
	for range s.cleanupTicker.C {
		s.cleanupExpiredSessions()
	}
}

// cleanupExpiredSessions removes expired sessions and cleans up memory
func (s *SessionStore) cleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			s.secureSessionCleanup(session)
			delete(s.sessions, sessionID)
			atomic.AddInt64(&s.activeCount, -1)

			s.auditLogger.LogSessionEvent("session_expired", session, map[string]interface{}{
				"cleanup_time": now,
				"duration":     now.Sub(session.CreatedAt),
			})
		}
	}
}

// secureSessionCleanup performs secure cleanup of session data
func (s *SessionStore) secureSessionCleanup(session *Session) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Securely clear session key
	if session.SessionKey != nil {
		s.secureZero(session.SessionKey)
		s.unprotectMemoryRegion(unsafe.Pointer(&session.SessionKey[0]), len(session.SessionKey))
	}

	// Clear encrypted data
	if session.EncryptedData != nil {
		s.secureZero(session.EncryptedData)
	}

	// Clear key derivation salt
	if session.KeyDerivationSalt != nil {
		s.secureZero(session.KeyDerivationSalt)
	}

	// Clear device context
	for _, deviceSession := range session.DeviceContext {
		// Clear sensitive command history
		for i := range deviceSession.CommandHistory {
			deviceSession.CommandHistory[i].Output = ""
		}
	}

	// Force garbage collection to clear any remaining references
	runtime.GC()
}

// protectMemoryRegion protects a memory region from swapping
func (s *SessionStore) protectMemoryRegion(ptr unsafe.Pointer, size int) {
	s.memoryProtector.mu.Lock()
	defer s.memoryProtector.mu.Unlock()

	addr := uintptr(ptr)
	if err := unix.Mlock((*byte)(ptr), size); err != nil {
		// Log warning but continue - this is a best-effort security measure
		s.auditLogger.LogSecurityEvent("memory_lock_failed", "medium",
			map[string]interface{}{
				"address": fmt.Sprintf("0x%x", addr),
				"size":    size,
				"error":   err.Error(),
			})
	} else {
		s.memoryProtector.allocations[addr] = size
	}
}

// unprotectMemoryRegion removes memory protection
func (s *SessionStore) unprotectMemoryRegion(ptr unsafe.Pointer, size int) {
	s.memoryProtector.mu.Lock()
	defer s.memoryProtector.mu.Unlock()

	addr := uintptr(ptr)
	if _, exists := s.memoryProtector.allocations[addr]; exists {
		unix.Munlock((*byte)(ptr), size)
		delete(s.memoryProtector.allocations, addr)
	}
}

// secureZero securely zeroes memory using constant-time operations
func (s *SessionStore) secureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Use subtle.ConstantTimeCopy to avoid compiler optimizations
	zeros := make([]byte, len(data))
	subtle.ConstantTimeCopy(1, data, zeros)
}

// generateSecureSessionID generates a cryptographically secure session ID
func (s *SessionStore) generateSecureSessionID() (string, error) {
	// Generate 32 bytes of random data
	randomBytes, err := s.hsm.SecureRandom(32)
	if err != nil {
		return "", err
	}

	// Hash with current timestamp for additional entropy
	hash := sha256.New()
	hash.Write(randomBytes)
	hash.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))

	sessionID := hex.EncodeToString(hash.Sum(nil))
	return sessionID, nil
}

// memoryProtectionRoutine monitors memory protection status
func (s *SessionStore) memoryProtectionRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.checkMemoryProtection()
	}
}

// checkMemoryProtection verifies memory protection is still active
func (s *SessionStore) checkMemoryProtection() {
	s.memoryProtector.mu.RLock()
	protectedRegions := len(s.memoryProtector.allocations)
	s.memoryProtector.mu.RUnlock()

	if protectedRegions > 0 {
		s.auditLogger.LogSecurityEvent("memory_protection_check", "info",
			map[string]interface{}{
				"protected_regions": protectedRegions,
				"active_sessions":   atomic.LoadInt64(&s.activeCount),
			})
	}
}

// ExtendSession extends session timeout if activity is recent
func (s *SessionStore) ExtendSession(sessionID string, extensionDuration time.Duration) error {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found")
	}

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Only extend if recent activity
	if time.Since(session.LastActivity) < 5*time.Minute {
		session.ExpiresAt = time.Now().Add(extensionDuration)
		s.auditLogger.LogSessionEvent("session_extended", session, map[string]interface{}{
			"extension_duration": extensionDuration,
		})
	}

	return nil
}

// SessionConfig holds configuration for session management
type SessionConfig struct {
	MaxSessions     int64
	SessionTimeout  time.Duration
	CleanupInterval time.Duration
	HSMConfig       HSMConfig
	AuditLogger     AuditLogger
}

// HSMConfig holds hardware security module configuration
type HSMConfig struct {
	Provider   string
	KeyStore   string
	CertPath   string
	ConfigPath string
}