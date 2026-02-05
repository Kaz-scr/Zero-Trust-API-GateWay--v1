package auth

import "context"

// AuthType represents how the request was authenticated.
type AuthType string

const (
	AuthJWT    AuthType = "jwt"
	AuthAPIKey AuthType = "api_key"
)

// Identity represents the authenticated caller.
type Identity struct {
	Type     AuthType
	Subject  string   // JWT sub OR API key ID
	Roles    []string // extracted roles
	Issuer   string   // JWT issuer (empty for API keys)
	Audience string   // JWT audience (empty for API keys)
}

type contextKey string

const identityKey contextKey = "auth_identity"

// WithIdentity attaches identity to request context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// FromContext retrieves identity from request context.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok
}
