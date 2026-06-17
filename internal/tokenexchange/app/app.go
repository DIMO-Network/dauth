package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/config"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/contracts/sacd"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/contracts/template"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/controllers/httpcontroller"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/controllers/rpc"
	_ "github.com/DIMO-Network/dauth/internal/tokenexchange/docs" // registers the generated OpenAPI spec
	"github.com/DIMO-Network/dauth/internal/tokenexchange/middleware"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services/access"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services/sacdproxy"
	templatesvs "github.com/DIMO-Network/dauth/internal/tokenexchange/services/template"
	txgrpc "github.com/DIMO-Network/dauth/pkg/grpc"
	"github.com/DIMO-Network/shared/pkg/middleware/metrics"
	"github.com/ethereum/go-ethereum/ethclient"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"google.golang.org/grpc"
)

// CreateServers creates the HTTP handler and gRPC server for the application.
func CreateServers(logger zerolog.Logger, settings *config.Settings) (http.Handler, *grpc.Server, error) {
	keys, err := keyset.Load(config.SigningKeys())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signing keys: %w", err)
	}
	ttl := 10 * time.Minute
	if settings.TokenExpiration != "" {
		ttl, err = time.ParseDuration(settings.TokenExpiration)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid TOKEN_EXPIRATION %q: %w", settings.TokenExpiration, err)
		}
	}
	signer := services.NewTokenSigner(keys, settings.Issuer, ttl)

	ethClient, err := ethclient.Dial(settings.BlockchainNodeURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial Ethereum RPC: %w", err)
	}

	ipfsService, err := services.NewIPFSClient(&logger, settings.IPFSBaseURL, settings.IPFSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IPFS client: %w", err)
	}

	sacdContract, err := sacd.NewSacd(settings.ContractAddressSacd, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	prox := &sacdproxy.Proxy{
		HTTP: &http.Client{
			Timeout: 5 * time.Second, // TODO(elffjs): Configurable?
		},
		QueryEndpoint:          settings.IdentityURL,
		Contract:               sacdContract,
		ContractAddressVehicle: settings.ContractAddressVehicle,
	}

	templateContract, err := template.NewTemplate(settings.ContractAddressTemplate, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	templateService, err := templatesvs.NewTemplateService(templateContract, ipfsService, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create template service: %w", err)
	}

	accessService, err := access.NewAccessService(ipfsService, prox, templateService, ethClient, settings.ContractAddressManufacturer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create access service: %w", err)
	}

	handler, err := createHTTPServer(logger, settings, keys, signer, accessService)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create http server: %w", err)
	}

	grpcServer := createGRPCServer(rpc.NewTokenExchangeServer(accessService))

	return handler, grpcServer, nil
}

func createHTTPServer(logger zerolog.Logger, settings *config.Settings, keys *keyset.KeySet, signer *services.TokenSigner, accessService *access.Service) (http.Handler, error) {
	httpCtrl, err := httpcontroller.NewTokenExchangeController(settings, signer, accessService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token exchange controller: %w", err)
	}
	idSvc := services.NewIdentityController(&logger, settings)
	devLicense := middleware.NewDevLicenseValidator(idSvc, logger)

	jwtAuth, err := middleware.NewJWTAuth(settings.JWKKeySetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to build JWT auth middleware: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", healthCheck)

	// Interactive OpenAPI docs, served over net/http (replaces the Fiber
	// swagger handler; the generated spec is unchanged).
	mux.Handle("GET /v1/swagger/", httpSwagger.WrapHandler)

	// This service signs permission tokens with its own keyset and publishes the
	// public halves here, taking over the JWKS endpoint DEX used to serve.
	mux.Handle("GET /keys", jwksHandler(keys))
	mux.Handle("GET /.well-known/jwks.json", jwksHandler(keys))
	mux.Handle("GET /.well-known/openid-configuration", discoveryHandler(settings.Issuer))

	// The exchange endpoint requires a valid (signature-checked) dauth token from
	// a registered developer license.
	exchange := jwtAuth(devLicense(http.HandlerFunc(httpCtrl.ExchangeToken)))
	mux.Handle("POST /v1/tokens/exchange", exchange)

	return recoverMiddleware(logger)(mux), nil
}

func createGRPCServer(rpcCtrl *rpc.TokenExchangeServer) *grpc.Server {
	grpcPanic := metrics.GRPCPanicker{}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanic.GRPCPanicRecoveryHandler)),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)
	txgrpc.RegisterTokenExchangeServiceServer(server, rpcCtrl)
	return server
}

func healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":"Server is up and running"}`))
}

// jwksHandler serves the public halves of this service's signing keys as a JWKS
// (RFC 7517) for downstream validators.
func jwksHandler(keys *keyset.KeySet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := keys.JWKS()
		if err != nil {
			http.Error(w, "failed to render JWKS", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

// discoveryHandler serves a minimal OIDC discovery document pointing at this
// service's issuer and JWKS.
func discoveryHandler(issuer string) http.Handler {
	doc, _ := json.Marshal(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"token"},
		"subject_types_supported":               []string{"public"},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})
}

// recoverMiddleware turns a handler panic into a 500 instead of crashing the
// process, logging the recovered value.
func recoverMiddleware(log zerolog.Logger) func(http.Handler) http.Handler {
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
