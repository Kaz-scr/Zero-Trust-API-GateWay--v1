package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"Zero-TrustAPIGateWayServer/internal/auth"
)

func TestRBACAllowsMatchingRole(t *testing.T) {
	policies := PolicySet{
		Policies: []Policy{
			{
				Method: "GET",
				Path:   "/api",
				Roles:  []string{"admin"},
			},
		},
	}

	handler := RBACMiddleware(policies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	id := &auth.Identity{
		Roles: []string{"admin"},
	}

	req := httptest.NewRequest("GET", "/api/resource", nil)
	req = req.WithContext(auth.WithIdentity(context.Background(), id))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRBACDeniesMissingRole(t *testing.T) {
	policies := PolicySet{
		Policies: []Policy{
			{
				Method: "POST",
				Path:   "/admin",
				Roles:  []string{"admin"},
			},
		},
	}

	handler := RBACMiddleware(policies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	id := &auth.Identity{
		Roles: []string{"user"},
	}

	req := httptest.NewRequest("POST", "/admin", nil)
	req = req.WithContext(auth.WithIdentity(context.Background(), id))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestRBACDeniesNoIdentity(t *testing.T) {
	policies := PolicySet{}

	handler := RBACMiddleware(policies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestRBACPathPrefixMatch(t *testing.T) {
	policies := PolicySet{
		Policies: []Policy{
			{
				Method: "GET",
				Path:   "/api/public",
				Roles:  []string{"user"},
			},
		},
	}

	handler := RBACMiddleware(policies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	id := &auth.Identity{
		Roles: []string{"user"},
	}

	req := httptest.NewRequest("GET", "/api/public/items", nil)
	req = req.WithContext(auth.WithIdentity(context.Background(), id))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (path prefix match), got %d", rr.Code)
	}
}
