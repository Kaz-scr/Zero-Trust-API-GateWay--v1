package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

/*
AUDIT LOGGING DESIGN

append only file logging.
 Simple
 Auditable
 No external dependencies
 Easy to reason about failure modes

hash chaining.
 Detects deletion, modification, or reordering
 Tamper evident, not tamper proof by design

fail open.
 Logging failure must never block request handling
 Availability audit completeness in live traffic
*/

type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	lastHash string
}

// NewLogger opens (or creates) an append only audit log file.
func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return nil, err
	}

	return &Logger{
		file:     f,
		lastHash: "",
	}, nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	return l.file.Close()
}

func (l *Logger) Log(method, path, decision, reason string) {
	// Fail open never panic outward
	defer func() {
		_ = recover()
	}()

	l.mu.Lock()
	defer l.mu.Unlock()

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Method:    method,
		Path:      path,
		Decision:  decision,
		Reason:    reason,
		PrevHash:  l.lastHash,
	}

	entry.Hash = computeHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	_, err = l.file.Write(append(data, '\n'))
	if err != nil {
		return
	}

	l.lastHash = entry.Hash
}

/*
hashing
*/

func computeHash(e Entry) string {
	h := sha256.New()

	h.Write([]byte(e.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(e.Method))
	h.Write([]byte(e.Path))
	h.Write([]byte(e.Decision))
	h.Write([]byte(e.Reason))
	h.Write([]byte(e.PrevHash))

	return hex.EncodeToString(h.Sum(nil))
}
