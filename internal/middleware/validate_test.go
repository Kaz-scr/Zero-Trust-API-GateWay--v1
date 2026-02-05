package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestHandler() http.Handler {
	return ValidateRequestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func baseRequest(body []byte) *http.Request {
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestValidRequestPasses(t *testing.T) {
	handler := newTestHandler()

	req := baseRequest([]byte(`{"ok":true}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMissingRequiredHeader(t *testing.T) {
	handler := newTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestInvalidContentType(t *testing.T) {
	handler := newTestHandler()

	req := baseRequest([]byte(`data`))
	req.Header.Set("Content-Type", "application/xml")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOversizedRequestBody(t *testing.T) {
	handler := newTestHandler()

	oversized := make([]byte, MaxRequestBodyBytes+1)
	req := baseRequest(oversized)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected rejection, got %d", rr.Code)
	}
}

func TestNoBodyNoContentType(t *testing.T) {
	handler := newTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "test-agent")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestBodyPreservedForDownstream(t *testing.T) {
	payload := []byte(`{"foo":"bar"}`)
	handler := ValidateRequestMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	req := baseRequest(payload)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), payload) {
		t.Fatalf("expected body %q, got %q", payload, rr.Body.Bytes())
	}
}
