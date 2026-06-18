package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const tokenCtxKey ctxKey = "token"

// NewJWTAuth returns middleware that validates the Bearer token's RS256
// signature against the JWKS at jwksURL and stores the parsed token in the
// request context. Like the Fiber jwtware it replaces, it is signature-only:
// it does not enforce iss or aud (downstream validators do that). After cutover
// jwksURL points at dauth's /keys.
func NewJWTAuth(jwksURL string) (func(http.Handler) http.Handler, error) {
	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("failed to build keyfunc from %q: %w", jwksURL, err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))

	mw := func(next http.Handler) http.Handler {
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
	return mw, nil
}

// TokenFromContext returns the validated JWT stored by NewJWTAuth.
func TokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	t, ok := ctx.Value(tokenCtxKey).(*jwt.Token)
	return t, ok
}

// WithToken stores a validated JWT in ctx. NewJWTAuth uses it after verifying a
// token; it is also exported so tests can inject a token without a real JWKS.
func WithToken(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}
