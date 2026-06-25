package message

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestMessageString(t *testing.T) {
	issued := time.Date(2026, 6, 14, 17, 20, 0, 0, time.UTC)
	m := Message{
		Domain:         "auth.dimo.zone",
		Address:        common.HexToAddress("0x6e4f5e1a8b2c3d4e5f60718293a4b5c6d7e8f901"),
		Statement:      "Sign in to DIMO.",
		URI:            "https://auth.dimo.zone",
		ChainID:        137,
		Nonce:          "abc123",
		IssuedAt:       issued,
		ExpirationTime: issued.Add(5 * time.Minute),
	}

	want := "auth.dimo.zone wants you to sign in with your Ethereum account:\n" +
		common.HexToAddress("0x6e4f5e1a8b2c3d4e5f60718293a4b5c6d7e8f901").Hex() + "\n\n" +
		"Sign in to DIMO.\n\n" +
		"URI: https://auth.dimo.zone\n" +
		"Version: 1\n" +
		"Chain ID: 137\n" +
		"Nonce: abc123\n" +
		"Issued At: 2026-06-14T17:20:00Z\n" +
		"Expiration Time: 2026-06-14T17:25:00Z"

	assert.Equal(t, want, m.String())
}

func TestMessageStringUsesChecksummedAddress(t *testing.T) {
	// A lowercase input address must render in EIP-55 checksum form.
	m := Message{
		Domain:         "auth.dimo.zone",
		Address:        common.HexToAddress("0x07b584f6a7125491c991ca2a45ab9e641b1cee1b"),
		Statement:      "Sign in.",
		URI:            "https://auth.dimo.zone",
		ChainID:        1,
		Nonce:          "n",
		IssuedAt:       time.Unix(0, 0).UTC(),
		ExpirationTime: time.Unix(60, 0).UTC(),
	}
	assert.Contains(t, m.String(), "0x07B584f6a7125491C991ca2a45ab9e641B1CeE1b")
}
