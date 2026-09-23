// Package dpop implements the proof-of-possession half of RFC 9449: a client
// signs a short-lived proof JWT with its own key for every request, and a
// server checks the proof against the request and against the key thumbprint
// the access token was bound to (cnf.jkt). Both sides live here so the issuer
// (dauth), the resource server (dq) and clients agree on one profile.
//
// The profile: proofs are ES256 (P-256) or RS256, carry the public key in the
// jwk header, and claim jti, htm, htu and iat; a proof presented with an
// access token also claims ath, the token's SHA-256. A proof is accepted once.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// HeaderName is the HTTP header a proof travels in.
const HeaderName = "DPoP"

// TokenType is the token_type of a DPoP-bound access token, and the
// Authorization scheme it is presented under.
const TokenType = "DPoP"

// typ is the JOSE typ of a proof.
const typ = "dpop+jwt"

// ErrInvalid is wrapped by every verification failure.
var ErrInvalid = errors.New("invalid DPoP proof")

// Verifier checks proofs.
type Verifier struct {
	// MaxAge is how old a proof's iat may be; zero means five minutes.
	MaxAge time.Duration
	// Skew is how far in the future iat may be; zero means one minute.
	Skew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	replay *replayCache
}

// NewVerifier returns a Verifier with a replay cache that remembers every
// accepted jti for MaxAge.
func NewVerifier() *Verifier {
	return &Verifier{replay: newReplayCache()}
}

func (v *Verifier) maxAge() time.Duration {
	if v.MaxAge > 0 {
		return v.MaxAge
	}
	return 5 * time.Minute
}

func (v *Verifier) skew() time.Duration {
	if v.Skew > 0 {
		return v.Skew
	}
	return time.Minute
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

type proofClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
}

// Validate implements jwt.Claims with no registered-claim checks; the
// verifier applies the profile's own.
func (proofClaims) Validate() error { return nil }

func (proofClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (proofClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (proofClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (proofClaims) GetIssuer() (string, error)                   { return "", nil }
func (proofClaims) GetSubject() (string, error)                  { return "", nil }
func (proofClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

// Verify checks proof against an HTTP request with the given method and URL,
// and against accessToken when one was presented (the ath claim is then
// required). It returns the thumbprint of the key that signed the proof; the
// caller compares it to the access token's cnf.jkt.
func (v *Verifier) Verify(proof, method, requestURL, accessToken string) (string, error) {
	var claims proofClaims
	var jkt string
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256", "RS256"}), jwt.WithoutClaimsValidation())
	_, err := parser.ParseWithClaims(proof, &claims, func(t *jwt.Token) (any, error) {
		if got, _ := t.Header["typ"].(string); got != typ {
			return nil, fmt.Errorf("typ must be %s", typ)
		}
		raw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, errors.New("jwk header is required")
		}
		if _, private := raw["d"]; private {
			return nil, errors.New("jwk must be a public key")
		}
		key, err := publicKey(raw)
		if err != nil {
			return nil, err
		}
		if jkt, err = Thumbprint(raw); err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	if claims.JTI == "" {
		return "", fmt.Errorf("%w: jti is required", ErrInvalid)
	}
	if !strings.EqualFold(claims.HTM, method) {
		return "", fmt.Errorf("%w: htm %q does not match %s", ErrInvalid, claims.HTM, method)
	}
	if NormalizeURI(claims.HTU) != NormalizeURI(requestURL) {
		return "", fmt.Errorf("%w: htu %q does not match the request", ErrInvalid, claims.HTU)
	}
	now := v.now()
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || iat.Before(now.Add(-v.maxAge())) || iat.After(now.Add(v.skew())) {
		return "", fmt.Errorf("%w: iat is outside the accepted window", ErrInvalid)
	}
	if accessToken != "" {
		if claims.ATH == "" {
			return "", fmt.Errorf("%w: ath is required when presenting an access token", ErrInvalid)
		}
		if claims.ATH != hash(accessToken) {
			return "", fmt.Errorf("%w: ath does not match the access token", ErrInvalid)
		}
	}
	if v.replay != nil && !v.replay.add(claims.JTI, now.Add(v.maxAge()+v.skew()), now) {
		return "", fmt.Errorf("%w: proof replayed", ErrInvalid)
	}
	return jkt, nil
}

// NormalizeURI reduces a URL to what htu compares on: scheme, host and path,
// without query or fragment, with scheme and host lowercased.
func NormalizeURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// Thumbprint computes the RFC 7638 thumbprint of a JWK given as its JSON
// members: base64url(SHA-256(canonical JSON of the required members)).
func Thumbprint(jwk map[string]any) (string, error) {
	var members []string
	switch jwk["kty"] {
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	default:
		return "", fmt.Errorf("unsupported kty %v", jwk["kty"])
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, m := range members {
		val, ok := jwk[m].(string)
		if !ok || val == "" {
			return "", fmt.Errorf("jwk member %s is required", m)
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		k, _ := json.Marshal(m)
		v, _ := json.Marshal(val)
		sb.Write(k)
		sb.WriteByte(':')
		sb.Write(v)
	}
	sb.WriteByte('}')
	return hash(sb.String()), nil
}

// publicKey turns a JWK into a verification key.
func publicKey(jwk map[string]any) (crypto.PublicKey, error) {
	switch jwk["kty"] {
	case "EC":
		if jwk["crv"] != "P-256" {
			return nil, fmt.Errorf("unsupported crv %v", jwk["crv"])
		}
		x, err := b64Int(jwk["x"])
		if err != nil {
			return nil, fmt.Errorf("jwk x: %w", err)
		}
		y, err := b64Int(jwk["y"])
		if err != nil {
			return nil, fmt.Errorf("jwk y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !pub.IsOnCurve(x, y) {
			return nil, errors.New("jwk point is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, err := b64Int(jwk["n"])
		if err != nil {
			return nil, fmt.Errorf("jwk n: %w", err)
		}
		e, err := b64Int(jwk["e"])
		if err != nil {
			return nil, fmt.Errorf("jwk e: %w", err)
		}
		if !e.IsInt64() || e.Int64() < 3 || n.BitLen() < 2048 {
			return nil, errors.New("jwk RSA key is too weak")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %v", jwk["kty"])
	}
}

func b64Int(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, errors.New("missing")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Key is a client's DPoP key: a P-256 key that signs proofs.
type Key struct {
	priv *ecdsa.PrivateKey
	jwk  map[string]any
	jkt  string
}

// GenerateKey makes a fresh P-256 DPoP key.
func GenerateKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewKey(priv)
}

// NewKey wraps an existing P-256 key.
func NewKey(priv *ecdsa.PrivateKey) (*Key, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("DPoP keys must be P-256")
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, size))),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, size))),
	}
	jkt, err := Thumbprint(jwk)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, jwk: jwk, jkt: jkt}, nil
}

// Thumbprint is the key's RFC 7638 thumbprint, what a bound token's cnf.jkt
// holds.
func (k *Key) Thumbprint() string { return k.jkt }

// Proof signs a proof for a request with the given method and URL, made at
// time now. accessToken, when not empty, is the token the request presents
// and is hashed into ath.
func (k *Key) Proof(method, requestURL, accessToken string, now time.Time) (string, error) {
	claims := proofClaims{JTI: uuid.NewString(), HTM: method, HTU: NormalizeURI(requestURL), IAT: now.Unix()}
	if accessToken != "" {
		claims.ATH = hash(accessToken)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = typ
	tok.Header["jwk"] = k.jwk
	return tok.SignedString(k.priv)
}
