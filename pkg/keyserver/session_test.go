package keyserver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSession(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{
		{Operation: "encrypt", KeyID: "key-abc"},
		{Operation: "decrypt", KeyID: "key-abc"},
	}

	session, err := mgr.CreateSession(ctx, "agent-1", caps, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)
	assert.Equal(t, "agent-1", session.ClientID)
	assert.Len(t, session.Capabilities, 2)
	assert.False(t, session.IsExpired())
}

func TestCreateSessionNoCaps(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	_, err := mgr.CreateSession(ctx, "agent", nil, time.Hour)
	assert.Error(t, err)
}

func TestCreateSessionZeroTTL(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{{Operation: "encrypt", KeyID: "*"}}
	_, err := mgr.CreateSession(ctx, "agent", caps, 0)
	assert.Error(t, err)
}

func TestValidateSession(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{
		{Operation: "encrypt", KeyID: "key-1"},
	}

	session, _ := mgr.CreateSession(ctx, "agent", caps, time.Hour)

	// Should succeed: has encrypt:key-1
	err := mgr.ValidateSession(ctx, session.ID, "encrypt", "key-1")
	assert.NoError(t, err)

	// Should fail: does not have decrypt capability
	err = mgr.ValidateSession(ctx, session.ID, "decrypt", "key-1")
	assert.Error(t, err)

	// Should fail: wrong key
	err = mgr.ValidateSession(ctx, session.ID, "encrypt", "key-2")
	assert.Error(t, err)
}

func TestWildcardCapability(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{
		{Operation: "decrypt", KeyID: "*"},
	}

	session, _ := mgr.CreateSession(ctx, "agent", caps, time.Hour)

	// Wildcard should match any key
	assert.NoError(t, mgr.ValidateSession(ctx, session.ID, "decrypt", "key-1"))
	assert.NoError(t, mgr.ValidateSession(ctx, session.ID, "decrypt", "key-2"))
	assert.NoError(t, mgr.ValidateSession(ctx, session.ID, "decrypt", "any-key"))

	// But not other operations
	assert.Error(t, mgr.ValidateSession(ctx, session.ID, "encrypt", "key-1"))
}

func TestExpiredSession(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{{Operation: "encrypt", KeyID: "*"}}

	// Create session with 1ms TTL
	session, _ := mgr.CreateSession(ctx, "agent", caps, time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	err := mgr.ValidateSession(ctx, session.ID, "encrypt", "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestRevokedSession(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{{Operation: "encrypt", KeyID: "*"}}
	session, _ := mgr.CreateSession(ctx, "agent", caps, time.Hour)

	// Works before revocation
	assert.NoError(t, mgr.ValidateSession(ctx, session.ID, "encrypt", "key-1"))

	// Revoke
	err := mgr.RevokeSession(ctx, session.ID)
	require.NoError(t, err)

	// Fails immediately after revocation
	err = mgr.ValidateSession(ctx, session.ID, "encrypt", "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestRevokeNonExistent(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	err := mgr.RevokeSession(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestValidateNonExistent(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	err := mgr.ValidateSession(ctx, "nonexistent", "encrypt", "key-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSession(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{{Operation: "encrypt", KeyID: "key-1"}}
	session, _ := mgr.CreateSession(ctx, "agent-x", caps, time.Hour)

	got, err := mgr.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, "agent-x", got.ClientID)
}

func TestCleanExpired(t *testing.T) {
	ctx := context.Background()
	mgr := NewSessionManager()

	caps := []Capability{{Operation: "encrypt", KeyID: "*"}}

	// Create one short-lived and one long-lived session
	mgr.CreateSession(ctx, "short", caps, time.Millisecond)
	mgr.CreateSession(ctx, "long", caps, time.Hour)

	time.Sleep(5 * time.Millisecond)

	cleaned := mgr.CleanExpired()
	assert.Equal(t, 1, cleaned)
}

func TestParseCapability(t *testing.T) {
	tests := []struct {
		input string
		want  Capability
		err   bool
	}{
		{"encrypt:key-abc", Capability{"encrypt", "key-abc"}, false},
		{"decrypt:*", Capability{"decrypt", "*"}, false},
		{"sign:key-123", Capability{"sign", "key-123"}, false},
		{"bogus:key", Capability{}, true},
		{"encrypt", Capability{}, true},
		{"encrypt:", Capability{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseCapability(tt.input)
			if tt.err {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestParseCapabilities(t *testing.T) {
	caps, err := ParseCapabilities("encrypt:key-1, decrypt:key-1, list:*")
	require.NoError(t, err)
	assert.Len(t, caps, 3)
	assert.Equal(t, "encrypt", caps[0].Operation)
	assert.Equal(t, "key-1", caps[0].KeyID)
	assert.Equal(t, "*", caps[2].KeyID)
}

func TestCapabilityString(t *testing.T) {
	c := Capability{Operation: "encrypt", KeyID: "key-abc"}
	assert.Equal(t, "encrypt:key-abc", c.String())
}
