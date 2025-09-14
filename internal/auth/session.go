package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Session represents a user session
type Session struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	CreatedAt     time.Time `json:"created_at"`
	LastActivity  time.Time `json:"last_activity"`
	ExpiresAt     time.Time `json:"expires_at"`
	EncryptedData string    `json:"-"`
	User          *User     `json:"user"`
}

// Credentials holds user credentials (encrypted in session)
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// SessionStore manages user sessions
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	timeout  time.Duration
	gcTicker *time.Ticker
}

// NewSessionStore creates a new session store
func NewSessionStore(timeout time.Duration) *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*Session),
		timeout:  timeout,
		gcTicker: time.NewTicker(5 * time.Minute),
	}

	// Start garbage collection routine
	go store.cleanupRoutine()

	return store
}

// CreateSession creates a new session for a user
func (s *SessionStore) CreateSession(user *User, credentials *Credentials) (*Session, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate session ID
	sessionID := generateSessionID()

	// Encrypt credentials
	encryptedCreds, err := encryptCredentials(credentials)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Create session
	session := &Session{
		ID:            sessionID,
		Username:      user.Username,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		ExpiresAt:     time.Now().Add(s.timeout),
		EncryptedData: encryptedCreds,
		User:          user,
	}

	// Store session
	s.sessions[sessionID] = session

	// Generate JWT token
	token, err := generateToken(sessionID, user.Username)
	if err != nil {
		delete(s.sessions, sessionID)
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	return session, token, nil
}

// GetSession retrieves a session by ID
func (s *SessionStore) GetSession(sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()

	// Extend session if activity is near expiry
	if time.Until(session.ExpiresAt) < 30*time.Minute {
		session.ExpiresAt = time.Now().Add(s.timeout)
	}

	return session, nil
}

// GetCredentials decrypts and returns stored credentials
func (s *SessionStore) GetCredentials(sessionID string) (*Credentials, error) {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	credentials, err := decryptCredentials(session.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	return credentials, nil
}

// DeleteSession removes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear encrypted data before deletion
	if session, exists := s.sessions[sessionID]; exists {
		session.EncryptedData = ""
	}

	delete(s.sessions, sessionID)
}

// cleanupRoutine removes expired sessions
func (s *SessionStore) cleanupRoutine() {
	for range s.gcTicker.C {
		s.mu.Lock()
		now := time.Now()
		for id, session := range s.sessions {
			if now.After(session.ExpiresAt) {
				// Clear encrypted data
				session.EncryptedData = ""
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// encryptCredentials encrypts credentials using AES-GCM
func encryptCredentials(creds *Credentials) (string, error) {
	// Generate a new AES key for this session
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Marshal credentials
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Combine key and ciphertext for storage
	combined := append(key, ciphertext...)

	// Base64 encode for storage
	return base64.StdEncoding.EncodeToString(combined), nil
}

// decryptCredentials decrypts credentials
func decryptCredentials(encryptedData string) (*Credentials, error) {
	// Base64 decode
	combined, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	// Extract key and ciphertext
	key := combined[:32]
	ciphertext := combined[32:]

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal credentials
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

// generateToken creates a JWT token for a session
func generateToken(sessionID, username string) (string, error) {
	claims := jwt.MapClaims{
		"session_id": sessionID,
		"username":   username,
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// TODO: Use actual secret from config
	return token.SignedString([]byte("change-this-secret-in-production"))
}