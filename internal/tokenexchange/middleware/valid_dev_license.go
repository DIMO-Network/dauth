package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const (
	// ethereumAddressClaim is the claim on the inbound dauth token identifying
	// the address the caller has proven control of.
	ethereumAddressClaim = "ethereum_address"

	responseSubjectCtxKey ctxKey = "responseSubject"
)

type IdentityService interface {
	IsDevLicense(ctx context.Context, ethAddr common.Address) (bool, error)
}

// NewDevLicenseValidator confirms the caller holds a valid developer license.
// The caller's address comes from the ethereum_address claim on the inbound
// dauth token (validated upstream by NewJWTAuth); it must resolve to a
// registered developer license, and it becomes the response subject (and the
// grantee for the access check). The DIMO mobile app carries a developer
// license like any other integrator, so there is no special passthrough.
func NewDevLicenseValidator(idSvc IdentityService, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := TokenFromContext(r.Context())
			if !ok {
				http.Error(w, "no token in request context", http.StatusUnauthorized)
				return
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "unexpected token claims type", http.StatusBadRequest)
				return
			}

			addrStr, _ := claims[ethereumAddressClaim].(string)
			if !common.IsHexAddress(addrStr) {
				http.Error(w, "no valid ethereum_address claim", http.StatusUnauthorized)
				return
			}
			clientAddress := common.HexToAddress(addrStr)

			valid, err := idSvc.IsDevLicense(r.Context(), clientAddress)
			if err != nil {
				http.Error(w, "developer license lookup failed", http.StatusInternalServerError)
				return
			}
			if !valid {
				logger.Debug().Str("address", clientAddress.Hex()).Msg("not a dev license")
				http.Error(w, fmt.Sprintf("not a dev license: %s", clientAddress), http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), responseSubjectCtxKey, clientAddress.Hex())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetResponseSubject returns the checksummed address of the developer license
// making the request, to be used as the JWT sub field of the token in the
// response to the client.
func GetResponseSubject(ctx context.Context) (string, error) {
	addr, ok := ctx.Value(responseSubjectCtxKey).(string)
	if !ok {
		return "", ErrNoSubject
	}
	return addr, nil
}

// ErrNoSubject indicates that the subject of the token in the response
// was not found in the request context. This suggests that the dev license
// middleware was skipped or has a bug.
var ErrNoSubject = errors.New("no subject value found in request context")
