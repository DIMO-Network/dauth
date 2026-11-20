// Package nonce stores the short-lived, single-use challenges issued during
// sign-in. dauth holds the challenge text here, keyed by its nonce, so the
// token endpoint can find the outstanding challenge from the nonce the client
// returns, check the request against it without spending it, consume the entry
// atomically once the request holds the key it names, and verify the signature
// against the stored copy, giving true single-use replay protection. The store
// is the only server-side state in the login flow; the issued JWTs remain
// stateless.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// ErrNotFound means the challenge is unknown, already consumed, or expired. All
// three are reported identically so the response never reveals which.
var ErrNotFound = errors.New("challenge not found, already used, or expired")

// Challenge is the data dauth retains for an outstanding sign-in.
type Challenge struct {
	Message   string    // the challenge text the DID's key signs
	DID       string    // DID that must sign Message
	ExpiresAt time.Time // absolute expiry
	// Audience is the `aud` to stamp on the issued token: the resolved value
	// (the requested audience, or the issuer's default when none was asked
	// for), bound here at challenge time so the token carries exactly the
	// audience the challenge text names and cannot be swapped at /token time.
	Audience []string
	// Scopes and JKT are the token's scopes and the thumbprint of the DPoP
	// key it will be bound to, fixed at challenge time like Audience; the
	// challenge text names both, so the DID's signature covers them.
	Scopes []string
	JKT    string
}

// Store records and atomically consumes challenges, keyed by nonce. The
// methods take a context so a database-backed store (see Postgres) can bind its
// work to the request's lifetime; the in-memory store ignores it.
type Store interface {
	// Put records ch under the given nonce.
	Put(ctx context.Context, nonce string, ch Challenge) error
	// Peek returns the challenge for nonce without consuming it, so /token
	// can check a request against it before anything is spent or stored. It
	// returns ErrNotFound if absent or expired.
	Peek(ctx context.Context, nonce string) (Challenge, error)
	// Consume removes and returns the challenge for nonce, but only when it is
	// bound to the DPoP key thumbprint jkt; a challenge bound to another key
	// stays in place. It returns ErrNotFound if the challenge is absent,
	// expired, already consumed or bound to another key. Consuming is
	// single-use: of any number of calls for one nonce, at most one succeeds.
	Consume(ctx context.Context, nonce, jkt string) (Challenge, error)
}

// New returns a fresh, cryptographically random nonce (32 bytes, hex-encoded).
// It is embedded in the challenge text and also serves as the store key and
// the handle returned to the client.
func New() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
