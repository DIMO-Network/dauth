// Package siwe builds Sign-In With Ethereum (EIP-4361) messages. dauth always
// constructs the canonical message itself and stores it server-side keyed by
// nonce, so the bytes the wallet signs are exactly the bytes dauth verifies —
// there is no client-supplied message to re-parse and no canonicalization gap
// for an attacker to exploit.
package siwe

import (
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Version is the only EIP-4361 version dauth emits.
const Version = "1"

// Message holds the fields of a Sign-In With Ethereum request.
type Message struct {
	Domain         string         // RFC 4501 dnsauthority requesting the sign-in
	Address        common.Address // account signing in (EIP-55 checksummed in output)
	Statement      string         // human-readable assertion shown in the wallet
	URI            string         // subject of the sign-in (the issuer URL)
	ChainID        uint64         // EIP-155 chain id the sign-in is bound to
	Nonce          string         // single-use randomized token
	IssuedAt       time.Time      // when the message was generated
	ExpirationTime time.Time      // when the message is no longer valid
}

// String renders the canonical EIP-4361 string the wallet must personal_sign.
// The layout matches the EIP-4361 ABNF for a message with a statement and an
// expiration time; both are always present in dauth's messages.
func (m Message) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s wants you to sign in with your Ethereum account:\n", m.Domain)
	b.WriteString(m.Address.Hex())
	b.WriteString("\n\n")
	b.WriteString(m.Statement)
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "URI: %s\n", m.URI)
	fmt.Fprintf(&b, "Version: %s\n", Version)
	fmt.Fprintf(&b, "Chain ID: %d\n", m.ChainID)
	fmt.Fprintf(&b, "Nonce: %s\n", m.Nonce)
	fmt.Fprintf(&b, "Issued At: %s\n", m.IssuedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Expiration Time: %s", m.ExpirationTime.UTC().Format(time.RFC3339))
	return b.String()
}
