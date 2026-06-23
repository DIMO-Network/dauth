package app

// General OpenAPI annotations for the permission (/permissions) surface. These
// live here — not on the merged cmd/dauth main — so they are scanned only for
// the permission spec (instance "swagger") and never leak into the sign-in spec
// (instance "dauth", generated from ./cmd/dauth,./internal/server).
//
// @title                      DIMO Token Exchange API
// @version                    1.0
// @BasePath                   /permissions
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
//
//go:generate go tool swag init -g doc.go -d ./internal/tokenexchange/app,./internal/tokenexchange/controllers/httpcontroller -o ./internal/tokenexchange/docs --parseInternal
