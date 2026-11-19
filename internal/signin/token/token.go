// Package token mints the identity tokens dauth issues after a successful
// sign-in. Tokens are short-lived, RS256-signed, and fully self-contained: any
// validator with the JWKS can verify them offline, so issuance keeps no server
// state. The org host accepts them as member identity (plan §1 decision B) and
// /exchange takes one as the caller's identity. Every token carries the
// scopes the DID signed for and is bound to the DPoP key it named
// (did-directory pkg/identity), so it is good only for what was asked and
// only in the hands of that key.
package token

import (
	"errors"
	"slices"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/identity"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the identity-token claim set: the registered claims, with sub the
// signed-in DID, plus scope and the key binding.
type Claims struct {
	jwt.RegisteredClaims
	Scope string                 `json:"scope"`
	Cnf   *identity.Confirmation `json:"cnf"`
}

// Request is what a token is issued for.
type Request struct {
	// DID is the sub.
	DID string
	// Audience overrides the configured default aud when not empty.
	Audience []string
	// Scopes are the token's scopes; at least one.
	Scopes []string
	// JKT is the thumbprint of the DPoP key the token is bound to.
	JKT string
}

// Issuer mints signed identity tokens for verified DIDs.
type Issuer struct {
	keys     *keyset.KeySet
	issuer   string
	audience jwt.ClaimStrings
	ttl      time.Duration
	// approveTTL is the lifetime of a token carrying the approve scope.
	approveTTL time.Duration
	now        func() time.Time // injectable for tests
}

// Config configures an Issuer.
type Config struct {
	Keys     *keyset.KeySet
	Issuer   string
	Audience []string
	TTL      time.Duration
	// ApproveTTL is the lifetime of a token carrying the approve scope, kept
	// short so approving is close to signing in again; zero means TTL.
	ApproveTTL time.Duration
	// Now overrides the clock; nil uses time.Now.
	Now func() time.Time
}

// NewIssuer builds an Issuer from cfg.
func NewIssuer(cfg Config) *Issuer {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	approveTTL := cfg.ApproveTTL
	if approveTTL <= 0 {
		approveTTL = cfg.TTL
	}
	return &Issuer{
		keys:       cfg.Keys,
		issuer:     cfg.Issuer,
		audience:   jwt.ClaimStrings(cfg.Audience),
		ttl:        cfg.TTL,
		approveTTL: approveTTL,
		now:        now,
	}
}

// Issue mints a signed identity token for req, and returns it and its expiry
// time. A token carrying the approve scope lives for the approve lifetime.
//
// A non-empty req.Audience overrides the configured default; the caller is
// responsible for having validated it, and req.Scopes, against what it allows.
// Issue trusts what it is given, except that a token always has a scope and a
// key.
func (i *Issuer) Issue(req Request) (string, time.Time, error) {
	return i.IssueFor(req, i.TTLFor(req.Scopes))
}

// IssueFor is Issue with an explicit lifetime, for the service's own
// short-lived tokens.
func (i *Issuer) IssueFor(req Request, ttl time.Duration) (string, time.Time, error) {
	if len(req.Scopes) == 0 {
		return "", time.Time{}, errors.New("an identity token needs a scope")
	}
	if req.JKT == "" {
		return "", time.Time{}, errors.New("an identity token needs a key to be bound to")
	}
	now := i.now().UTC()
	exp := now.Add(ttl)

	aud := i.audience
	if len(req.Audience) > 0 {
		aud = jwt.ClaimStrings(req.Audience)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   req.DID,
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
		Scope: identity.FormatScope(req.Scopes),
		Cnf:   &identity.Confirmation{JKT: req.JKT},
	}

	signed, err := i.keys.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// TTLFor is the lifetime of a token carrying scopes, for the expires_in
// response field.
func (i *Issuer) TTLFor(scopes []string) time.Duration {
	if slices.Contains(scopes, identity.ScopeApprove) {
		return i.approveTTL
	}
	return i.ttl
}

// DefaultAudience is the aud a token gets when its request names none.
func (i *Issuer) DefaultAudience() []string { return slices.Clone(i.audience) }
