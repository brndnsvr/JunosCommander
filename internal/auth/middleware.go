package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Middleware provides JWT authentication middleware for API routes
func Middleware(store *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Extract token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// TODO: Use actual secret from config
			return []byte("change-this-secret-in-production"), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		// Get session ID from claims
		sessionID, ok := claims["session_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing session ID"})
			c.Abort()
			return
		}

		// Validate session
		session, err := store.GetSession(sessionID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
			c.Abort()
			return
		}

		// Set user context
		c.Set("session", session)
		c.Set("user", session.User)
		c.Set("username", session.Username)

		c.Next()
	}
}

// WebMiddleware provides session-based authentication for web routes
func WebMiddleware(store *SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session cookie
		sessionCookie, err := c.Cookie("session_token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Parse token
		token, err := jwt.Parse(sessionCookie, func(token *jwt.Token) (interface{}, error) {
			return []byte("change-this-secret-in-production"), nil
		})

		if err != nil || !token.Valid {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Get session ID
		sessionID, ok := claims["session_id"].(string)
		if !ok {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Validate session
		session, err := store.GetSession(sessionID)
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Set user context
		c.Set("session", session)
		c.Set("user", session.User)
		c.Set("username", session.Username)

		c.Next()
	}
}