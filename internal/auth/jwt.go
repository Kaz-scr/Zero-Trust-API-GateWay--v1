package auth

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
SECURITY NOTES:
- RS256 only (explicitly enforced)
- No "alg=none"
- No token issuance
- Claims are validated manually and explicitly
*/

type JWTConfig struct {
	Issuer    string
	Audience  string
	PublicKey *rsa.PublicKey
}

func JWTMiddleware(cfg JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
				return
			}

			tokenStr := parts[1]

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				// Explicitly enforce RS256
				if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return cfg.PublicKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid token claims", http.StatusUnauthorized)
				return
			}

			// Validate issuer
			if claims["iss"] != cfg.Issuer {
				http.Error(w, "invalid token issuer", http.StatusUnauthorized)
				return
			}

			// Validate audience
			if aud, ok := claims["aud"].(string); !ok || aud != cfg.Audience {
				http.Error(w, "invalid token audience", http.StatusUnauthorized)
				return
			}

			// Validate expiration
			exp, ok := claims["exp"].(float64)
			if !ok || time.Now().Unix() > int64(exp) {
				http.Error(w, "token expired", http.StatusUnauthorized)
				return
			}

			sub, ok := claims["sub"].(string)
			if !ok || sub == "" {
				http.Error(w, "token subject missing", http.StatusUnauthorized)
				return
			}

			roles := extractRoles(claims)

			id := &Identity{
				Type:     AuthJWT,
				Subject:  sub,
				Roles:    roles,
				Issuer:   cfg.Issuer,
				Audience: cfg.Audience,
			}

			ctx := WithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractRoles(claims jwt.MapClaims) []string {
	raw, ok := claims["roles"]
	if !ok {
		return nil
	}

	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}

	var roles []string
	for _, r := range list {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles
}
