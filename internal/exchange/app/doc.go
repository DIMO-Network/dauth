package app

// General OpenAPI annotations for the exchange (/exchange) surface. These
// live here — not on the merged cmd/dauth main — so they are scanned only for
// the exchange spec (instance "swagger") and never leak into the sign-in spec
// (instance "dauth", generated from ./cmd/dauth,./internal/server).
//
// @title                      DIMO Token Exchange API
// @version                    1.0
// @BasePath                   /exchange
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
//
//go:generate go tool swag init -g doc.go -d ./internal/exchange/app,./internal/exchange/controllers/httpcontroller -o ./internal/exchange/docs --parseInternal
