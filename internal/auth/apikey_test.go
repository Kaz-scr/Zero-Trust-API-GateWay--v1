package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockStore struct {
	key *APIKey
}

func (m *mockStore) Lookup(k string) (*APIKey, bool) {
	if m.key != nil && k == m.key.Key {
		return m.key, true
	}
	return nil, false
}

func TestAPIKeyMiddlewareRejectsMissingKey(t *testing.T) {
	store := &mockStore{}

	handler := APIKeyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAPIKeyMiddlewareAllowsValidKey(t *testing.T) {
	testKey := "test-key-123"
	store := &mockStore{
		key: &APIKey{ID: "test-id", Key: testKey, Roles: []string{"admin", "user"}},
	}

	handler := APIKeyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("identity not in context")
		}
		if id.Subject != "test-id" {
			t.Fatalf("expected subject test-id, got %s", id.Subject)
		}
		if len(id.Roles) != 2 {
			t.Fatalf("expected 2 roles, got %d", len(id.Roles))
		}
		hasAdmin := false
		hasUser := false
		for _, role := range id.Roles {
			if role == "admin" {
				hasAdmin = true
			}
			if role == "user" {
				hasUser = true
			}
		}
		if !hasAdmin || !hasUser {
			t.Fatalf("expected roles [admin, user], got %v", id.Roles)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", testKey)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAPIKeyMiddlewareRejectsInvalidKey(t *testing.T) {
	store := &mockStore{
		key: &APIKey{ID: "test-id", Key: "valid-key", Roles: []string{"admin"}},
	}

	handler := APIKeyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", "wrong-key-not-in-store")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAPIKeyMiddlewareSkipsHealth(t *testing.T) {
	store := &mockStore{} // empty no valid keys

	handler := APIKeyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	// no x-api-key header
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (health bypass), got %d", rr.Code)
	}
}
