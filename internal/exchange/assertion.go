package exchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// A client assertion is how an app attests that a request comes through it
// (design spec §11.1 step 4). It is a short JWT the app signs with a key its
// own DID document lists, in the shape of RFC 7523's client authentication
// assertion, addressed to this exchange, used once, and bound to the caller's
// DPoP key:
//
//	header  {"alg": "ES256", "kid": "<app DID>#<fragment>"}
//	claims  {"iss": <app DID>, "sub": <app DID>, "aud": <exchange URL>,
//	         "iat", "exp" (at most five minutes later), "jti",
//	         "cnf": {"jkt": <thumbprint of the caller's DPoP key>}}
//
// It is not an identity token and signs nobody in. An identity token would
// do both jobs at once: whoever held an app's token could present it as that
// app's sign-in anywhere that token was accepted, and replay it as the
// assertion for any caller for as long as it lived. Binding cnf.jkt to the
// proof on the same request means an assertion the app handed one caller
// cannot be lifted into another caller's exchange.

// AssertionMaxAge bounds exp - iat on a client assertion.
const AssertionMaxAge = 5 * time.Minute

// assertionSkew is how far iat may sit in the future of this clock.
const assertionSkew = time.Minute

// ErrInvalidAssertion is a client assertion that does not verify.
var ErrInvalidAssertion = errors.New("invalid client assertion")

// ErrAssertionKeys means the app's DID document could not be fetched; the
// request should be retried, not refused.
var ErrAssertionKeys = errors.New("could not resolve the app's keys")

// KeyVerifier checks a signature against a verification method a DID
// document lists: base64url r||s ECDSA over the SHA-256 of data, which is the
// JWS form of ES256. The sign-in surface's Verifier is one.
type KeyVerifier interface {
	Verify(ctx context.Context, did, fragment string, data []byte, sig string) error
}

// AssertionVerifier verifies client assertions.
type AssertionVerifier struct {
	Keys KeyVerifier
	// Audience is the aud an assertion must name: this exchange's URL.
	Audience string
	// IsUnavailable reports whether a Keys error means the directory could not
	// answer, as opposed to the key not verifying.
	IsUnavailable func(error) bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

func (v *AssertionVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

type assertionHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type assertionClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Iat int64           `json:"iat"`
	Exp int64           `json:"exp"`
	JTI string          `json:"jti"`
	Cnf *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// Verify checks raw as an assertion by an app for the caller holding the DPoP
// key jkt, and returns the app's DID.
func (v *AssertionVerifier) Verify(ctx context.Context, raw, jkt string) (string, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS", ErrInvalidAssertion)
	}
	var header assertionHeader
	if err := decodePart(parts[0], &header); err != nil {
		return "", fmt.Errorf("%w: header: %v", ErrInvalidAssertion, err)
	}
	if header.Alg != "ES256" {
		return "", fmt.Errorf("%w: alg must be ES256", ErrInvalidAssertion)
	}
	var claims assertionClaims
	if err := decodePart(parts[1], &claims); err != nil {
		return "", fmt.Errorf("%w: claims: %v", ErrInvalidAssertion, err)
	}

	app := claims.Iss
	did, fragment, ok := strings.Cut(header.Kid, "#")
	switch {
	case !isDID(app) || claims.Sub != app:
		return "", fmt.Errorf("%w: iss and sub must both be the app's DID", ErrInvalidAssertion)
	case !ok || did != app || fragment == "":
		return "", fmt.Errorf("%w: kid must name a verification method of the app's DID", ErrInvalidAssertion)
	case !audienceNames(claims.Aud, v.Audience):
		return "", fmt.Errorf("%w: aud must be %s", ErrInvalidAssertion, v.Audience)
	case claims.Cnf == nil || claims.Cnf.JKT == "" || claims.Cnf.JKT != jkt:
		return "", fmt.Errorf("%w: cnf.jkt must be the DPoP key of this request", ErrInvalidAssertion)
	case claims.JTI == "":
		return "", fmt.Errorf("%w: jti is required", ErrInvalidAssertion)
	}
	now := v.now()
	iat, exp := time.Unix(claims.Iat, 0), time.Unix(claims.Exp, 0)
	switch {
	case claims.Iat == 0 || claims.Exp == 0:
		return "", fmt.Errorf("%w: iat and exp are required", ErrInvalidAssertion)
	case !exp.After(iat) || exp.Sub(iat) > AssertionMaxAge:
		return "", fmt.Errorf("%w: exp must be after iat and at most %s later", ErrInvalidAssertion, AssertionMaxAge)
	case iat.After(now.Add(assertionSkew)):
		return "", fmt.Errorf("%w: issued in the future", ErrInvalidAssertion)
	case !now.Before(exp):
		return "", fmt.Errorf("%w: expired", ErrInvalidAssertion)
	}

	if err := v.Keys.Verify(ctx, app, fragment, []byte(parts[0]+"."+parts[1]), parts[2]); err != nil {
		if v.IsUnavailable != nil && v.IsUnavailable(err) {
			return "", fmt.Errorf("%w: %v", ErrAssertionKeys, err)
		}
		return "", fmt.Errorf("%w: signature: %v", ErrInvalidAssertion, err)
	}
	// Recorded only once the signature verifies, so nobody can burn an app's
	// jti with a forgery.
	if !v.remember(app+" "+claims.JTI, exp, now) {
		return "", fmt.Errorf("%w: already used", ErrInvalidAssertion)
	}
	return app, nil
}

// remember records an assertion id until it expires and reports false if it
// was already there. Like the DPoP replay cache it is per process; the short
// lifetime and the jkt binding bound what a replay on another replica gains.
func (v *AssertionVerifier) remember(id string, exp, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	for k, e := range v.seen {
		if !now.Before(e) {
			delete(v.seen, k)
		}
	}
	if _, ok := v.seen[id]; ok {
		return false
	}
	v.seen[id] = exp
	return true
}

func decodePart(part string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// audienceNames reports whether a JWT aud claim, a string or an array of
// strings, names want.
func audienceNames(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
