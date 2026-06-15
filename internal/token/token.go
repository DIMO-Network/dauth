// Package token mints the access JWTs dauth issues after a successful sign-in.
// Tokens are short-lived, RS256-signed, and fully self-contained: any validator
// with the JWKS can verify them offline, so issuance keeps no server state.
package token

import (
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the dauth access-token claim set. It embeds the registered claims
// (iss, sub, aud, exp, nbf, iat, jti) and adds ethereum_address — the canonical
// claim downstream services such as din read to identify the caller.
type Claims struct {
	EthereumAddress string `json:"ethereum_address"`
	jwt.RegisteredClaims
}

// Issuer mints signed access tokens for verified Ethereum accounts.
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

// Issue mints a signed access token for account. The subject and
// ethereum_address claim are the EIP-55 checksummed address. It returns the
// signed token and its expiry time.
func (i *Issuer) Issue(account common.Address) (string, time.Time, error) {
	now := i.now().UTC()
	exp := now.Add(i.ttl)
	addr := account.Hex()

	claims := Claims{
		EthereumAddress: addr,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   addr,
			Audience:  i.audience,
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
