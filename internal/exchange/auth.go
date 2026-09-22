package exchange

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

const callerKey ctxKey = "caller"

// NewIdentityAuth returns middleware that validates the Bearer identity token
// against the sign-in surface's JWKS (supplied in memory: the binary holds
// both keysets, so there is no self-referential fetch of its own /signin/keys
// at startup) and the sign-in issuer, and stores the token's sub, the caller's
// DID, in the request context.
func NewIdentityAuth(jwksJSON []byte, issuer string) (func(http.Handler) http.Handler, error) {
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to build keyfunc from in-memory JWKS: %w", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				writeError(w, http.StatusUnauthorized, "invalid_token", "authorization header must use the Bearer scheme with an identity token")
				return
			}
			var claims jwt.RegisteredClaims
			token, err := parser.ParseWithClaims(strings.TrimSpace(raw), &claims, jwks.Keyfunc)
			if err != nil || !token.Valid {
				writeError(w, http.StatusUnauthorized, "invalid_token", "identity token is invalid")
				return
			}
			if !isDID(claims.Subject) {
				writeError(w, http.StatusUnauthorized, "invalid_token", "identity token sub must be a DID")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), claims.Subject)))
		})
	}, nil
}

// WithCaller stores the authenticated caller's DID in ctx.
func WithCaller(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, callerKey, did)
}

// CallerFromContext returns the DID NewIdentityAuth stored.
func CallerFromContext(ctx context.Context) (string, bool) {
	did, ok := ctx.Value(callerKey).(string)
	return did, ok && did != ""
}

func isDID(s string) bool {
	rest, ok := strings.CutPrefix(s, "did:")
	if !ok {
		return false
	}
	method, id, ok := strings.Cut(rest, ":")
	return ok && method != "" && id != "" && !strings.ContainsAny(s, " \t\r\n#")
}
