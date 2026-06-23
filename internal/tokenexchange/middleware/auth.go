package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const tokenCtxKey ctxKey = "token"

// NewJWTAuthFromJWKS returns middleware that validates the Bearer token's RS256
// signature against a static JWKS supplied in memory, and stores the parsed
// token in the request context. Like the Fiber jwtware it replaces, it is
// signature-only: it does not enforce iss or aud (downstream validators do
// that). The merged binary builds it from the /siwe keyset directly, avoiding a
// self-referential HTTP fetch of its own /siwe/keys at startup (the listener
// isn't up yet).
func NewJWTAuthFromJWKS(jwksJSON []byte) (func(http.Handler) http.Handler, error) {
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to build keyfunc from in-memory JWKS: %w", err)
	}
	return authMiddleware(jwks), nil
}

// authMiddleware builds the signature-only Bearer-token middleware around a
// resolved keyfunc.
func authMiddleware(jwks keyfunc.Keyfunc) func(http.Handler) http.Handler {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				http.Error(w, "authorization header must use the Bearer scheme", http.StatusUnauthorized)
				return
			}
			token, err := parser.Parse(strings.TrimSpace(tokenStr), jwks.Keyfunc)
			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithToken(r.Context(), token)))
		})
	}
}

// TokenFromContext returns the validated JWT stored by NewJWTAuthFromJWKS.
func TokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	t, ok := ctx.Value(tokenCtxKey).(*jwt.Token)
	return t, ok
}

// WithToken stores a validated JWT in ctx. NewJWTAuthFromJWKS uses it after verifying a
// token; it is also exported so tests can inject a token without a real JWKS.
func WithToken(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}
