package audit

import (
	"os"
	"testing"
)

func newTempLogger(t *testing.T) (*Logger, string) {
	t.Helper()

	tmp, err := os.CreateTemp("", "audit*.log")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	logger, err := NewLogger(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	return logger, tmp.Name()
}

func TestLogEntryCreation(t *testing.T) {
	logger, path := newTempLogger(t)
	defer os.Remove(path)
	defer logger.Close()

	logger.Log("GET", "/test", "ALLOW", "test reason")

	if err := VerifyLogIntegrity(path); err != nil {
		t.Fatalf("log verification failed: %v", err)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	logger, path := newTempLogger(t)
	defer os.Remove(path)
	defer logger.Close()

	logger.Log("GET", "/a", "ALLOW", "ok")
	logger.Log("POST", "/b", "DENY", "blocked")

	if err := VerifyLogIntegrity(path); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}
}

func TestTamperingDetection(t *testing.T) {
	logger, path := newTempLogger(t)
	defer os.Remove(path)
	defer logger.Close()

	logger.Log("GET", "/a", "ALLOW", "ok")
	logger.Log("POST", "/b", "DENY", "blocked")

	// Tamper with the file
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"corrupted":true}` + "\n")
	f.Close()

	if err := VerifyLogIntegrity(path); err == nil {
		t.Fatal("expected tampering to be detected")
	}
}
