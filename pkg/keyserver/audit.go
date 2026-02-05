package keyserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEvent records a single crypto operation for the audit trail.
type AuditEvent struct {
	Timestamp time.Time `json:"ts"`
	SessionID string    `json:"session_id,omitempty"`
	Operation string    `json:"op"`
	KeyID     string    `json:"key_id,omitempty"`
	Success   bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	InputSize int       `json:"input_size"`
}

// AuditLogger writes append-only JSONL audit events.
type AuditLogger struct {
	file   *os.File
	mu     sync.Mutex
	events []AuditEvent // in-memory copy for querying
}

// NewAuditLogger creates or opens an audit log file for append-only writing.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("keyserver: open audit log: %w", err)
	}
	return &AuditLogger{file: f}, nil
}

// NewMemoryAuditLogger creates an in-memory-only audit logger (for testing).
func NewMemoryAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

// Log records an audit event. It is always appended — never overwritten or deleted.
func (a *AuditLogger) Log(event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.events = append(a.events, event)

	if a.file != nil {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("keyserver: marshal audit event: %w", err)
		}
		data = append(data, '\n')
		if _, err := a.file.Write(data); err != nil {
			return fmt.Errorf("keyserver: write audit event: %w", err)
		}
	}

	return nil
}

// LogOp is a convenience method for logging a successful operation.
func (a *AuditLogger) LogOp(sessionID, op, keyID string, inputSize int) {
	a.Log(AuditEvent{
		SessionID: sessionID,
		Operation: op,
		KeyID:     keyID,
		Success:   true,
		InputSize: inputSize,
	})
}

// LogError is a convenience method for logging a failed operation.
func (a *AuditLogger) LogError(sessionID, op, keyID string, inputSize int, err error) {
	a.Log(AuditEvent{
		SessionID: sessionID,
		Operation: op,
		KeyID:     keyID,
		Success:   false,
		Error:     err.Error(),
		InputSize: inputSize,
	})
}

// Query returns audit events matching the given filter criteria.
// All filter fields are optional — zero values are ignored.
type AuditQuery struct {
	SessionID string
	Operation string
	KeyID     string
	Since     time.Time
	Until     time.Time
}

// Query filters the in-memory audit log by the given criteria.
func (a *AuditLogger) Query(q AuditQuery) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	var results []AuditEvent
	for _, e := range a.events {
		if q.SessionID != "" && e.SessionID != q.SessionID {
			continue
		}
		if q.Operation != "" && e.Operation != q.Operation {
			continue
		}
		if q.KeyID != "" && e.KeyID != q.KeyID {
			continue
		}
		if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.Timestamp.After(q.Until) {
			continue
		}
		results = append(results, e)
	}
	return results
}

// All returns all audit events.
func (a *AuditLogger) All() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]AuditEvent, len(a.events))
	copy(result, a.events)
	return result
}

// Close flushes and closes the underlying file.
func (a *AuditLogger) Close() error {
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
