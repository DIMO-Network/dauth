// Package httpmw holds the net/http middleware shared by both binaries: body
// caps and panic recovery.
package httpmw

import (
	"net"
	"net/http"

	"github.com/rs/zerolog"
)

// MaxBytes caps request body reads at limit bytes.
func MaxBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Recover turns a handler panic into a 500 instead of crashing the process,
// logging the recovered value.
func Recover(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error().Interface("panic", v).Str("path", r.URL.Path).Msg("recovered from panic")
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RemoteIP returns the request's remote host address (without port), used as a
// key for request logging.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
