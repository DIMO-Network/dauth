package signer

import (
	"context"
	"errors"
	"math/big"
	"testing"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMessage = []byte("auth.dimo.zone wants you to sign in...")

func signEOA(t *testing.T, msg []byte) (common.Address, []byte) {
	t.Helper()
	priv, err := crypto.GenerateKey()
	require.NoError(t, err)
	addr := crypto.PubkeyToAddress(priv.PublicKey)
	sig, err := crypto.Sign(accounts.TextHash(msg), priv)
	require.NoError(t, err)
	return addr, sig
}

func TestVerifyEOA_Valid(t *testing.T) {
	addr, sig := signEOA(t, testMessage)
	v := New(nil, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, testMessage, sig)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyEOA_LegacyVByte(t *testing.T) {
	// Wallets that emit v in {27,28} must still verify.
	addr, sig := signEOA(t, testMessage)
	sig[64] += 27
	v := New(nil, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, testMessage, sig)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyEOA_WrongSigner(t *testing.T) {
	_, sig := signEOA(t, testMessage)
	other := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	v := New(nil, zerolog.Nop())
	ok, err := v.Verify(context.Background(), other, testMessage, sig)
	require.NoError(t, err)
	assert.False(t, ok, "a signature by a different key must not verify")
}

func TestVerifyEOA_ShortSignature(t *testing.T) {
	addr, _ := signEOA(t, testMessage)
	v := New(nil, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, testMessage, []byte{0x01, 0x02})
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyEOA_TamperedMessage(t *testing.T) {
	addr, sig := signEOA(t, testMessage)
	v := New(nil, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, []byte("a different message"), sig)
	require.NoError(t, err)
	assert.False(t, ok)
}

// fakeBackend implements just enough of bind.ContractBackend for the EIP-1271
// path: CodeAt (to mark the address as a contract) and CallContract (to return
// the isValidSignature result). The embedded interface is nil; any other method
// would panic, which is fine because the tested path never calls them.
type fakeBackend struct {
	bind.ContractBackend
	code    []byte
	callRet []byte
	callErr error
	codeErr error
}

func (f *fakeBackend) CodeAt(_ context.Context, _ common.Address, _ *big.Int) ([]byte, error) {
	return f.code, f.codeErr
}

func (f *fakeBackend) CallContract(_ context.Context, _ ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	return f.callRet, f.callErr
}

// abi-encoded bytes4 magic value: the 4 bytes right-padded to 32.
func encodedMagic() []byte {
	b := make([]byte, 32)
	copy(b, erc1271magicValue[:])
	return b
}

func TestVerifyERC1271_Valid(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	backend := &fakeBackend{code: []byte{0x60, 0x80}, callRet: encodedMagic()}
	v := New(backend, zerolog.Nop())
	// A bogus 65-byte signature; the contract (faked) decides validity.
	sig := make([]byte, 65)
	ok, err := v.Verify(context.Background(), contract, testMessage, sig)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyERC1271_WrongMagic(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	backend := &fakeBackend{code: []byte{0x60, 0x80}, callRet: make([]byte, 32)} // zero magic
	v := New(backend, zerolog.Nop())
	ok, err := v.Verify(context.Background(), contract, testMessage, make([]byte, 65))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerify_EOAAddressWithBadSig_IsInvalidNotBackendError(t *testing.T) {
	// An EOA address (no code) whose signature does not match must be reported
	// as invalid (false, nil), never as a backend error — even with a backend
	// configured.
	addr, sig := signEOA(t, testMessage)
	backend := &fakeBackend{code: nil} // no code => EOA
	v := New(backend, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, []byte("tampered"), sig)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerify_BackendCodeError_IsTransient(t *testing.T) {
	addr, sig := signEOA(t, testMessage)
	backend := &fakeBackend{codeErr: errors.New("dial tcp: timeout")}
	v := New(backend, zerolog.Nop())
	ok, err := v.Verify(context.Background(), addr, []byte("tampered"), sig)
	assert.False(t, ok)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackend), "RPC failure must wrap ErrBackend so the handler answers 503")
}

func TestVerify_ContractCallError_IsTransient(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	backend := &fakeBackend{code: []byte{0x60, 0x80}, callErr: errors.New("execution reverted")}
	v := New(backend, zerolog.Nop())
	ok, err := v.Verify(context.Background(), contract, testMessage, make([]byte, 65))
	assert.False(t, ok)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackend))
}
