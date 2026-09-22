package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const callerKey ctxKey = "caller"

// IdentityVerifier checks identity tokens from the sign-in surface: the
// caller's, presented as the Bearer token, and an app's, presented as the
// client assertion. Both are the same kind of token; what differs is whose
// DID is in sub.
type IdentityVerifier struct {
	jwks   keyfunc.Keyfunc
	parser *jwt.Parser
}

// NewIdentityVerifier builds a verifier over the sign-in surface's JWKS
// (supplied in memory: the binary holds both keysets, so there is no
// self-referential fetch of its own /signin/keys at startup) and issuer.
func NewIdentityVerifier(jwksJSON []byte, issuer string) (*IdentityVerifier, error) {
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to build keyfunc from in-memory JWKS: %w", err)
	}
	return &IdentityVerifier{
		jwks:   jwks,
		parser: jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithExpirationRequired()),
	}, nil
}

// ErrInvalidIdentity is returned for a token that does not verify or whose
// sub is not a DID.
var ErrInvalidIdentity = errors.New("invalid identity token")

// Verify checks raw and returns its subject, the DID it identifies.
func (v *IdentityVerifier) Verify(raw string) (string, error) {
	var claims jwt.RegisteredClaims
	token, err := v.parser.ParseWithClaims(strings.TrimSpace(raw), &claims, v.jwks.Keyfunc)
	if err != nil || !token.Valid {
		return "", ErrInvalidIdentity
	}
	if !isDID(claims.Subject) {
		return "", fmt.Errorf("%w: sub must be a DID", ErrInvalidIdentity)
	}
	return claims.Subject, nil
}

// Middleware validates the Bearer identity token and stores the caller's
// DID in the request context.
func (v *IdentityVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid_token", "authorization header must use the Bearer scheme with an identity token")
			return
		}
		did, err := v.Verify(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "identity token is invalid")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), did)))
	})
}

// WithCaller stores the authenticated caller's DID in ctx.
func WithCaller(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, callerKey, did)
}

// CallerFromContext returns the DID the middleware stored.
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
