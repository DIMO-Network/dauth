package exchange

import (
	"net/http"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/oidc"
)

// maxRequestBytes caps the exchange request body; the payload is small JSON.
const maxRequestBytes = 64 << 10

// Surface is the exchange's two handlers: the exchange itself, mounted at
// POST /exchange, and the discovery and JWKS routes, mounted under /exchange/.
type Surface struct {
	Exchange  http.Handler
	WellKnown http.Handler
}

// NewSurface wires the exchange behind the identity middleware.
func NewSurface(h *Handler, wk *oidc.WellKnown) Surface {
	mux := http.NewServeMux()
	mux.Handle("GET /keys", wk.JWKS())
	mux.Handle("GET /.well-known/jwks.json", wk.JWKS())
	mux.Handle("GET /.well-known/openid-configuration", wk.Discovery())
	return Surface{
		Exchange:  httpmw.MaxBytes(maxRequestBytes)(h.Identity.Middleware(h)),
		WellKnown: mux,
	}
}
