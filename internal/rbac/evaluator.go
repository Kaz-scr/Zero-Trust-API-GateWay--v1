package rbac

import (
	"net/http"
	"strings"

	"Zero-TrustAPIGateWayServer/internal/auth"
)

/*
RBAC DESIGN PRINCIPLES:

- Authorization happens AFTER authentication
- Auth middleware only proves *who* the caller is
- RBAC decides *what* they are allowed to do
- Default deny: no matching rule => reject
- No dynamic logic, no conditions, no expressions
*/

type Policy struct {
	Method string   // HTTP method: GET, POST, etc.
	Path   string   // Path prefix match (e.g. /api/admin)
	Roles  []string // Allowed roles
}

type PolicySet struct {
	Policies []Policy
}

// RBACMiddleware enforces role-based authorization.
// It assumes authentication has already happened and
// identity is present in request context.
func RBACMiddleware(policies PolicySet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Skip RBAC for health checks
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// Identity MUST exist at this point
			identity, ok := auth.FromContext(r.Context())
			if !ok {
				// Fail closed: unauthenticated access is forbidden
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}

			// Evaluate policies
			for _, p := range policies.Policies {

				// Method must match exactly
				if r.Method != p.Method {
					continue
				}

				// Path must match prefix
				if !strings.HasPrefix(r.URL.Path, p.Path) {
					continue
				}

				// Role intersection check
				if hasAllowedRole(identity.Roles, p.Roles) {
					// Explicit allow
					next.ServeHTTP(w, r)
					return
				}
			}

			// No policy matched => deny
			http.Error(w, "access denied", http.StatusForbidden)
		})
	}
}

func hasAllowedRole(userRoles, allowedRoles []string) bool {
	for _, ur := range userRoles {
		for _, ar := range allowedRoles {
			if ur == ar {
				return true
			}
		}
	}
	return false
}
