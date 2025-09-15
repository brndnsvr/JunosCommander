package auth

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/junoscommander/junoscommander/internal/config"
	"go.uber.org/zap"
)

// Manager handles authentication operations
type Manager struct {
	config *config.AuthConfig
	logger *zap.Logger
}

// NewManager creates a new authentication manager
func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	return &Manager{
		config: &cfg.Auth,
		logger: logger,
	}
}

// AuthenticateUser validates user credentials against LDAP/AD
func (m *Manager) AuthenticateUser(username, password string) (*User, error) {
	// Development mode bypass when AD is unreachable
	if os.Getenv("SERVER_MODE") == "development" && os.Getenv("DEV_AUTH_BYPASS") == "true" {
		// Check against environment variables for testing
		testUser := os.Getenv("TEST_USERNAME")
		testPass := os.Getenv("TEST_PASSWORD")

		if testUser != "" && testPass != "" && username == testUser && password == testPass {
			m.logger.Warn("Using development authentication bypass",
				zap.String("user", username))
			return &User{
				Username: username,
				Email:    fmt.Sprintf("%s@centersquaredc.com", username),
				Groups:   []string{"netadmins", "users"},
			}, nil
		}
	}

	// Parse LDAP server URL
	serverURL := strings.TrimPrefix(m.config.LDAPServer, "ldap://")
	serverURL = strings.TrimPrefix(serverURL, "ldaps://")

	// Connect to LDAP server with timeout
	var conn *ldap.Conn
	var err error

	// Add connection timeout for development environments
	ldap.DefaultTimeout = 5 * time.Second

	if m.config.UseTLS {
		conn, err = ldap.DialTLS("tcp", serverURL, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.Dial("tcp", serverURL)
	}

	if err != nil {
		m.logger.Error("Failed to connect to LDAP server",
			zap.String("server", serverURL),
			zap.Error(err))
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// First bind with service account if configured
	if m.config.ServiceUser != "" && m.config.ServicePassword != "" {
		err = conn.Bind(m.config.ServiceUser, m.config.ServicePassword)
		if err != nil {
			m.logger.Error("Service account bind failed",
				zap.String("user", m.config.ServiceUser),
				zap.Error(err))
			return nil, fmt.Errorf("service account authentication failed: %w", err)
		}

		// Search for user
		searchRequest := ldap.NewSearchRequest(
			m.config.LDAPBaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
			[]string{"dn", "cn", "mail", "memberOf"},
			nil,
		)

		sr, err := conn.Search(searchRequest)
		if err != nil || len(sr.Entries) != 1 {
			m.logger.Error("User search failed",
				zap.String("user", username),
				zap.Error(err))
			return nil, fmt.Errorf("user not found")
		}

		userDN := sr.Entries[0].DN

		// Bind with user credentials to verify password
		err = conn.Bind(userDN, password)
		if err != nil {
			m.logger.Warn("User authentication failed",
				zap.String("user", username),
				zap.Error(err))
			return nil, fmt.Errorf("invalid credentials")
		}

		// Extract user information
		user := &User{
			Username: username,
			Email:    sr.Entries[0].GetAttributeValue("mail"),
			Groups:   extractGroups(sr.Entries[0].GetAttributeValues("memberOf")),
		}

		m.logger.Info("User authenticated successfully",
			zap.String("user", username),
			zap.Strings("groups", user.Groups))

		return user, nil
	}

	// Direct bind with user credentials (simple auth)
	userDN := fmt.Sprintf("CN=%s,%s", username, m.config.LDAPBaseDN)
	err = conn.Bind(userDN, password)
	if err != nil {
		m.logger.Warn("Direct bind failed",
			zap.String("user", username),
			zap.Error(err))
		return nil, fmt.Errorf("invalid credentials")
	}

	return &User{
		Username: username,
		Email:    fmt.Sprintf("%s@example.com", username),
		Groups:   []string{"users"},
	}, nil
}

// extractGroups extracts group names from LDAP memberOf attributes
func extractGroups(memberOf []string) []string {
	groups := make([]string, 0, len(memberOf))
	for _, dn := range memberOf {
		// Extract CN from DN (e.g., CN=netadmins,OU=Groups,DC=example,DC=com)
		parts := strings.Split(dn, ",")
		for _, part := range parts {
			if strings.HasPrefix(part, "CN=") {
				groupName := strings.TrimPrefix(part, "CN=")
				groups = append(groups, strings.ToLower(groupName))
				break
			}
		}
	}
	return groups
}

// User represents an authenticated user
type User struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}