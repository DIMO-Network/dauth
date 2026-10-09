package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const callerKey ctxKey = "caller"

// IdentityVerifier checks the caller's identity token from the sign-in
// surface, presented under the DPoP scheme. The token must be addressed to the
// exchange: dauth issues one kind of identity token to every relying party,
// and aud is what keeps a token a user signed in with for somewhere else from
// minting access tokens as them. It must carry the read scope and be bound to
// a key; the handler checks the request's proof against that key.
type IdentityVerifier struct {
	jwks   keyfunc.Keyfunc
	parser *jwt.Parser
}

// NewIdentityVerifier builds a verifier over the sign-in surface's JWKS
// (supplied in memory: the binary holds both keysets, so there is no
// self-referential fetch of its own /signin/keys at startup), its issuer, and
// the audience a token must name.
func NewIdentityVerifier(jwksJSON []byte, issuer, audience string) (*IdentityVerifier, error) {
	if audience == "" {
		return nil, errors.New("an identity token audience is required")
	}
	jwks, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwksJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to build keyfunc from in-memory JWKS: %w", err)
	}
	return &IdentityVerifier{
		jwks:   jwks,
		parser: jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired()),
	}, nil
}

// ErrInvalidIdentity is returned for a token that does not verify or whose
// sub is not a DID.
var ErrInvalidIdentity = errors.New("invalid identity token")

// Caller is a verified identity token: the DID it names, the thumbprint of
// the key it is bound to, and the token itself, which the request's DPoP
// proof must hash into ath.
type Caller struct {
	DID   string
	JKT   string
	Token string
}

type identityClaims struct {
	jwt.RegisteredClaims
	Scope string                 `json:"scope"`
	Cnf   *identity.Confirmation `json:"cnf"`
}

// Verify checks raw and returns the caller it identifies.
func (v *IdentityVerifier) Verify(raw string) (Caller, error) {
	raw = strings.TrimSpace(raw)
	var claims identityClaims
	token, err := v.parser.ParseWithClaims(raw, &claims, v.jwks.Keyfunc)
	if err != nil || !token.Valid {
		return Caller{}, ErrInvalidIdentity
	}
	if !isDID(claims.Subject) {
		return Caller{}, fmt.Errorf("%w: sub must be a DID", ErrInvalidIdentity)
	}
	scopes, err := identity.ParseScope(claims.Scope)
	if err != nil {
		return Caller{}, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
	}
	if !slices.Contains(scopes, identity.ScopeRead) {
		return Caller{}, fmt.Errorf("%w: the exchange needs the read scope", ErrInsufficientScope)
	}
	if claims.Cnf == nil || claims.Cnf.JKT == "" {
		return Caller{}, fmt.Errorf("%w: token is not bound to a key (cnf.jkt)", ErrInvalidIdentity)
	}
	return Caller{DID: claims.Subject, JKT: claims.Cnf.JKT, Token: raw}, nil
}

// ErrInsufficientScope is returned for a valid token without the read scope.
var ErrInsufficientScope = errors.New("insufficient scope")

// Middleware validates the DPoP-scheme identity token and stores the caller
// in the request context.
func (v *IdentityVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), dpop.TokenType+" ")
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid_token", "authorization header must use the DPoP scheme with an identity token")
			return
		}
		caller, err := v.Verify(raw)
		switch {
		case errors.Is(err, ErrInsufficientScope):
			writeError(w, http.StatusForbidden, "insufficient_scope", err.Error())
			return
		case err != nil:
			writeError(w, http.StatusUnauthorized, "invalid_token", "identity token is invalid")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), caller)))
	})
}

// WithCaller stores the authenticated caller in ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey, c)
}

// CallerFromContext returns the caller the middleware stored.
func CallerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey).(Caller)
	return c, ok && c.DID != ""
}

func isDID(s string) bool {
	rest, ok := strings.CutPrefix(s, "did:")
	if !ok {
		return false
	}
	method, id, ok := strings.Cut(rest, ":")
	return ok && method != "" && id != "" && !strings.ContainsAny(s, " \t\r\n#")
}
