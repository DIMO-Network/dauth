package api

import (
	"errors"
	"net/http"

	"github.com/DIMO-Network/dauth/internal/exchange/middleware"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
)

const ethereumAddressClaimName = "ethereum_address"

var zeroAddr common.Address

// ErrNoEthAddr reports that the request's validated JWT carries no usable
// ethereum_address claim.
var ErrNoEthAddr = errors.New("no valid ethereum_address claim")

// GetUserEthAddr returns the Ethereum address from the validated JWT stored in
// the request context by the auth middleware.
func GetUserEthAddr(r *http.Request) (common.Address, error) {
	token, ok := middleware.TokenFromContext(r.Context())
	if !ok {
		return zeroAddr, ErrNoEthAddr
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return zeroAddr, ErrNoEthAddr
	}
	addrString, ok := claims[ethereumAddressClaimName].(string)
	if !ok || !common.IsHexAddress(addrString) {
		return zeroAddr, ErrNoEthAddr
	}
	return common.HexToAddress(addrString), nil
}
