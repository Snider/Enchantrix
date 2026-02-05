package keyserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
)

// Session represents an authenticated session with specific capabilities.
// Agents receive a session token that limits what operations they can perform
// and on which keys.
type Session struct {
	ID           string       `json:"id"`
	Capabilities []Capability `json:"capabilities"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
	ClientID     string       `json:"client_id"`
	revoked      bool
}

// IsExpired reports whether the session has passed its TTL.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// HasCapability checks whether this session grants the given operation on the given key.
func (s *Session) HasCapability(op, keyID string) bool {
	for _, cap := range s.Capabilities {
		if cap.Matches(op, keyID) {
			return true
		}
	}
	return false
}

// SessionManager manages session lifecycle: create, validate, revoke.
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// CreateSession creates a new session with the given capabilities and TTL.
func (m *SessionManager) CreateSession(ctx context.Context, clientID string, caps []Capability, ttl time.Duration) (*Session, error) {
	if len(caps) == 0 {
		return nil, fmt.Errorf("keyserver: session requires at least one capability")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("keyserver: session TTL must be positive")
	}

	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:           id,
		Capabilities: caps,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		ClientID:     clientID,
	}

	m.mu.Lock()
	m.sessions[id] = session
	m.mu.Unlock()

	return session, nil
}

// ValidateSession checks that a session exists, is not expired, is not revoked,
// and has the capability for the requested operation on the requested key.
func (m *SessionManager) ValidateSession(ctx context.Context, sessionID string, op string, keyID string) error {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("keyserver: session not found: %s", sessionID)
	}
	if session.revoked {
		return fmt.Errorf("keyserver: session revoked: %s", sessionID)
	}
	if session.IsExpired() {
		return fmt.Errorf("keyserver: session expired: %s", sessionID)
	}
	if !session.HasCapability(op, keyID) {
		return fmt.Errorf("keyserver: session %s does not have %s capability for key %s", sessionID, op, keyID)
	}

	return nil
}

// RevokeSession immediately invalidates a session.
func (m *SessionManager) RevokeSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("keyserver: session not found: %s", sessionID)
	}

	session.revoked = true
	return nil
}

// GetSession returns session metadata (for inspection/auditing).
func (m *SessionManager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("keyserver: session not found: %s", sessionID)
	}

	return session, nil
}

// CleanExpired removes expired sessions from memory.
func (m *SessionManager) CleanExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for id, session := range m.sessions {
		if session.IsExpired() {
			delete(m.sessions, id)
			count++
		}
	}
	return count
}

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("keyserver: failed to generate session ID: %w", err)
	}
	return fmt.Sprintf("ses_%x", b), nil
}
