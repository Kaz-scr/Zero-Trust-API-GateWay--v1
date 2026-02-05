package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
)

/*
SECURITY NOTES
 Keys are compared using constant time comparison
 No plaintext logging
 Fail closed on missing or invalid keys
*/

type APIKey struct {
	ID    string
	Key   string // hashed in real deployments
	Roles []string
}

type APIKeyStore interface {
	Lookup(key string) (*APIKey, bool)
}

// GenerateTestAPIKey creates a random API key for testing purposes.
// It returns both the APIKey struct (for store) and the raw key string (for HTTP headers).
func GenerateTestAPIKey(id string, roles []string) (*APIKey, string, error) {
	// Generate 32 random bytes and encode as hex (64 char string)
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate random key: %w", err)
	}

	keyString := hex.EncodeToString(randomBytes)

	apiKey := &APIKey{
		ID:    id,
		Key:   keyString,
		Roles: roles,
	}

	return apiKey, keyString, nil
}

// GenerateTestAPIKeySimple is a convenience function that generates a test key
// with a default ID and common test roles. Returns the raw key string for easy copying.
func GenerateTestAPIKeySimple() (string, error) {
	apiKey, keyString, err := GenerateTestAPIKey("test-key-001", []string{"read", "write"})
	if err != nil {
		return "", err
	}
	_ = apiKey // Store this if needed for your mock
	return keyString, nil
}

// MapStore is an in-memory API key store. Keys are the raw key string.
type MapStore map[string]*APIKey

// Lookup returns the APIKey for the given key, or (nil, false) if not found.
func (m MapStore) Lookup(key string) (*APIKey, bool) {
	if apiKey, ok := m[key]; ok {
		return apiKey, true
	}
	return nil, false
}

// NewDemoStore returns a pre-populated store with demo keys for testing.
// Demo keys (use in X-API-Key header):
//   - demo-admin: roles [admin] — for POST/DELETE /api/admin
//   - demo-user:  roles [user]  — for GET /api/public
func NewDemoStore() APIKeyStore {
	store := make(MapStore)

	// Demo admin key — full access to admin endpoints
	adminKey := "deef0admin0000000000000000000000000000000000000000000000000000"
	store[adminKey] = &APIKey{ID: "demo-admin", Key: adminKey, Roles: []string{"admin"}}

	// Demo user key — access to public endpoints only
	userKey := "deef0us3r0000000000000000000000000000000000000000000000000000"
	store[userKey] = &APIKey{ID: "demo-user", Key: userKey, Roles: []string{"user"}}

	return store
}

func APIKeyMiddleware(store APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Skip auth for health checks
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get("X-API-Key")
			if key == "" {
				http.Error(w, "missing API key", http.StatusUnauthorized)
				return
			}

			record, ok := store.Lookup(key)
			if !ok {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}

			// Constant-time comparison (defensive)
			if subtle.ConstantTimeCompare([]byte(key), []byte(record.Key)) != 1 {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}

			id := &Identity{
				Type:    AuthAPIKey,
				Subject: record.ID,
				Roles:   record.Roles,
			}

			ctx := WithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
