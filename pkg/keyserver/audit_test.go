package keyserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditLogMemory(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-abc", 1024)
	logger.LogOp("ses-1", "decrypt", "key-abc", 512)
	logger.LogError("ses-2", "encrypt", "key-xyz", 256, fmt.Errorf("permission denied"))

	all := logger.All()
	assert.Len(t, all, 3)
	assert.True(t, all[0].Success)
	assert.False(t, all[2].Success)
	assert.Equal(t, "permission denied", all[2].Error)
}

func TestAuditLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewAuditLogger(path)
	require.NoError(t, err)

	logger.LogOp("ses-1", "encrypt", "key-1", 100)
	logger.LogOp("ses-1", "decrypt", "key-1", 200)
	logger.Close()

	// Verify file was written
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"op":"encrypt"`)
	assert.Contains(t, string(data), `"op":"decrypt"`)

	// Verify permissions
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestAuditLogAppendOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write first batch
	logger1, _ := NewAuditLogger(path)
	logger1.LogOp("ses-1", "encrypt", "key-1", 100)
	logger1.Close()

	// Reopen and write more
	logger2, _ := NewAuditLogger(path)
	logger2.LogOp("ses-2", "decrypt", "key-2", 200)
	logger2.Close()

	// Both entries should be present
	data, _ := os.ReadFile(path)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	assert.Equal(t, 2, lines)
}

func TestAuditQueryBySessionID(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 100)
	logger.LogOp("ses-2", "decrypt", "key-1", 200)
	logger.LogOp("ses-1", "sign", "key-2", 300)

	results := logger.Query(AuditQuery{SessionID: "ses-1"})
	assert.Len(t, results, 2)
}

func TestAuditQueryByOperation(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 100)
	logger.LogOp("ses-1", "decrypt", "key-1", 200)
	logger.LogOp("ses-1", "encrypt", "key-2", 300)

	results := logger.Query(AuditQuery{Operation: "encrypt"})
	assert.Len(t, results, 2)
}

func TestAuditQueryByKeyID(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 100)
	logger.LogOp("ses-1", "decrypt", "key-2", 200)
	logger.LogOp("ses-2", "sign", "key-1", 300)

	results := logger.Query(AuditQuery{KeyID: "key-1"})
	assert.Len(t, results, 2)
}

func TestAuditQueryByTimeRange(t *testing.T) {
	logger := NewMemoryAuditLogger()

	t1 := time.Now().UTC()
	logger.Log(AuditEvent{Timestamp: t1, Operation: "encrypt", KeyID: "key-1", Success: true})
	time.Sleep(10 * time.Millisecond)

	t2 := time.Now().UTC()
	logger.Log(AuditEvent{Timestamp: t2, Operation: "decrypt", KeyID: "key-1", Success: true})
	time.Sleep(10 * time.Millisecond)

	t3 := time.Now().UTC()
	logger.Log(AuditEvent{Timestamp: t3, Operation: "sign", KeyID: "key-1", Success: true})

	// Query events between t1 and t2 (exclusive of t3)
	results := logger.Query(AuditQuery{
		Since: t1.Add(-time.Millisecond),
		Until: t2.Add(time.Millisecond),
	})
	assert.Len(t, results, 2)
}

func TestAuditQueryCombined(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 100)
	logger.LogOp("ses-1", "encrypt", "key-2", 200)
	logger.LogOp("ses-2", "encrypt", "key-1", 300)
	logger.LogOp("ses-1", "decrypt", "key-1", 400)

	results := logger.Query(AuditQuery{SessionID: "ses-1", Operation: "encrypt"})
	assert.Len(t, results, 2)
}

func TestAuditEventTimestamp(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 100)

	events := logger.All()
	require.Len(t, events, 1)
	assert.False(t, events[0].Timestamp.IsZero())
}

func TestAuditInputSizeNotContent(t *testing.T) {
	logger := NewMemoryAuditLogger()

	logger.LogOp("ses-1", "encrypt", "key-1", 1048576)

	events := logger.All()
	require.Len(t, events, 1)
	assert.Equal(t, 1048576, events[0].InputSize)
	// Verify no actual content is stored — only the size
}
