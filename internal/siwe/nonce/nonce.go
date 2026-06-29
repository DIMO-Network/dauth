// Package nonce stores the short-lived, single-use challenges issued during
// sign-in. dauth holds the canonical SIWE message here, keyed by its nonce, so
// the token endpoint can find the outstanding challenge from the nonce the
// client returns, verify the signature against the stored copy, and consume the
// entry atomically — giving true single-use replay protection. The store is the
// only server-side state in the login flow; the issued JWTs remain stateless.
package nonce

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ErrNotFound means the challenge is unknown, already consumed, or expired. All
// three are reported identically so the response never reveals which.
var ErrNotFound = errors.New("challenge not found, already used, or expired")

// Challenge is the data dauth retains for an outstanding sign-in.
type Challenge struct {
	Message   string         // canonical EIP-4361 string the wallet signs
	Address   common.Address // account that must sign Message
	ExpiresAt time.Time      // absolute expiry
	// Audience is the `aud` to stamp on the issued token, bound here at
	// challenge time so it cannot be swapped at /token time. Empty means the
	// issuer's configured default audience.
	Audience []string
}

// Store records and atomically consumes challenges, keyed by nonce. The two
// methods take a context so a database-backed store (see Postgres) can bind its
// work to the request's lifetime; the in-memory store ignores it.
type Store interface {
	// Put records ch under the given nonce.
	Put(ctx context.Context, nonce string, ch Challenge) error
	// Consume removes and returns the challenge for nonce. It returns
	// ErrNotFound if absent or expired. Consuming is single-use: a second
	// call for the same nonce returns ErrNotFound.
	Consume(ctx context.Context, nonce string) (Challenge, error)
}

// New returns a fresh, cryptographically random nonce (32 bytes, hex-encoded).
// It is embedded in the SIWE message (per EIP-4361) and also serves as the
// store key and the handle returned to the client.
func New() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
