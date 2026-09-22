// Package token mints the identity tokens dauth issues after a successful
// sign-in. Tokens are short-lived, RS256-signed, and fully self-contained: any
// validator with the JWKS can verify them offline, so issuance keeps no server
// state. The org host accepts them as member identity (plan §1 decision B) and
// /exchange takes one as the caller's identity.
package token

import (
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the identity-token claim set: the registered claims, with sub the
// signed-in DID.
type Claims struct {
	jwt.RegisteredClaims
}

// Issuer mints signed identity tokens for verified DIDs.
type Issuer struct {
	keys     *keyset.KeySet
	issuer   string
	audience jwt.ClaimStrings
	ttl      time.Duration
	now      func() time.Time // injectable for tests
}

// Config configures an Issuer.
type Config struct {
	Keys     *keyset.KeySet
	Issuer   string
	Audience []string
	TTL      time.Duration
	// Now overrides the clock; nil uses time.Now.
	Now func() time.Time
}

// NewIssuer builds an Issuer from cfg.
func NewIssuer(cfg Config) *Issuer {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Issuer{
		keys:     cfg.Keys,
		issuer:   cfg.Issuer,
		audience: jwt.ClaimStrings(cfg.Audience),
		ttl:      cfg.TTL,
		now:      now,
	}
}

// Issue mints a signed identity token whose subject is did. It returns the
// signed token and its expiry time.
//
// audience overrides the `aud` claim for this token; when empty the issuer's
// configured default audience is used. The caller is responsible for having
// validated any non-default audience against its allow-list; Issue trusts what
// it is given.
func (i *Issuer) Issue(did string, audience []string) (string, time.Time, error) {
	return i.IssueFor(did, audience, i.ttl)
}

// IssueFor is Issue with an explicit lifetime, for the service's own
// short-lived tokens.
func (i *Issuer) IssueFor(did string, audience []string, ttl time.Duration) (string, time.Time, error) {
	now := i.now().UTC()
	exp := now.Add(ttl)

	aud := i.audience
	if len(audience) > 0 {
		aud = jwt.ClaimStrings(audience)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   did,
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}

	signed, err := i.keys.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// TTL is the lifetime of issued tokens, exposed for the expires_in response
// field.
func (i *Issuer) TTL() time.Duration { return i.ttl }
