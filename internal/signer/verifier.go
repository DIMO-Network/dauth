// Package signer verifies that an Ethereum account authorized a message. It
// supports externally-owned accounts (ECDSA recovery) and deployed smart
// accounts (EIP-1271 isValidSignature), mirroring din's attestation verifier.
package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/DIMO-Network/dauth/internal/web3"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
)

// erc1271magicValue is the bytes4 isValidSignature returns for a valid
// signature, per EIP-1271.
var erc1271magicValue = [4]byte{0x16, 0x26, 0xba, 0x7e}

// ErrBackend marks a failure to *determine* validity because the Ethereum
// backend was unavailable (no RPC configured, dial/timeout, contract call
// error). It is distinct from a signature that is simply invalid: the caller
// should answer 503, not 401, so a transient RPC outage is retryable.
var ErrBackend = errors.New("signature verification backend unavailable")

// Verifier checks signatures. EOA signatures are verified locally; smart
// account (EIP-1271) signatures are checked against the account contract via
// the configured Ethereum backend.
type Verifier struct {
	logger  zerolog.Logger
	backend bind.ContractBackend // nil disables EIP-1271 checks
}

// New returns a Verifier using backend for EIP-1271 checks. A nil backend
// restricts verification to EOA signatures.
func New(backend bind.ContractBackend, logger zerolog.Logger) *Verifier {
	return &Verifier{logger: logger, backend: backend}
}

// Verify reports whether signer authorized message. message is the raw
// EIP-4361 string; it is hashed with the EIP-191 personal_sign prefix before
// recovery, matching what wallets sign. A false result with a nil error means
// the signature is genuinely invalid. A non-nil error wrapping ErrBackend means
// validity could not be determined (RPC unavailable) and the request should be
// retried.
//
// Dispatch: try EOA recovery first. If it fails and a backend is configured,
// use the account's on-chain code as the discriminator — an address with no
// code is an EOA whose signature simply did not match (invalid, not a backend
// error), while an address with code is a smart account checked via EIP-1271.
// With no backend, verification is EOA-only.
func (v *Verifier) Verify(ctx context.Context, signer common.Address, message, signature []byte) (bool, error) {
	hash := accounts.TextHash(message)

	if verifyEOA(signature, hash, signer) {
		return true, nil
	}
	if v.backend == nil {
		return false, nil // EOA-only deployment: the EOA check is authoritative.
	}

	code, err := v.backend.CodeAt(ctx, signer, nil)
	if err != nil {
		return false, fmt.Errorf("%w: fetching code for %s: %v", ErrBackend, signer, err)
	}
	if len(code) == 0 {
		return false, nil // EOA with a non-matching signature.
	}

	ok, err := v.verifyERC1271(ctx, signature, common.BytesToHash(hash), signer)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrBackend, err)
	}
	return ok, nil
}

// verifyEOA recovers the signer from an ECDSA signature and compares it to the
// expected address. A malformed signature simply fails (returns false) — it is
// reported as an invalid signature, not a backend error.
func verifyEOA(signature, hash []byte, expected common.Address) bool {
	if len(signature) != 65 {
		return false
	}
	sig := make([]byte, 65)
	copy(sig, signature)

	// Normalize the recovery id (v). EIP-155/yellow-paper uses 27/28; some
	// devices (e.g. Ledger) emit 0/1. crypto.SigToPub wants 0/1.
	switch sig[64] {
	case 27, 28:
		sig[64] -= 27
	case 0, 1:
		// already normalized
	default:
		return false
	}

	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false
	}
	return crypto.PubkeyToAddress(*pub) == expected
}

// verifyERC1271 asks the account contract whether the signature is valid.
func (v *Verifier) verifyERC1271(ctx context.Context, signature []byte, hash common.Hash, account common.Address) (bool, error) {
	contract, err := web3.NewErc1271(account, v.backend)
	if err != nil {
		return false, fmt.Errorf("binding contract %s: %w", account, err)
	}
	result, err := contract.IsValidSignature(&bind.CallOpts{Context: ctx}, hash, signature)
	if err != nil {
		return false, fmt.Errorf("calling isValidSignature on %s: %w", account, err)
	}
	return result == erc1271magicValue, nil
}
