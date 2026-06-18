package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
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

	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:          settings.Issuer,
		JWKSURI:         settings.Issuer + "/keys",
		Keys:            keys,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "asset", "permissions", "cloud_events"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to render well-known surface: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", healthCheck)

	// Interactive OpenAPI docs, served over net/http (replaces the Fiber
	// swagger handler; the generated spec is unchanged).
	mux.Handle("GET /v1/swagger/", httpSwagger.WrapHandler)

	// This service signs permission tokens with its own keyset and publishes the
	// public halves here (shared oidc surface), taking over the JWKS endpoint DEX
	// used to serve.
	mux.Handle("GET /keys", wellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", wellKnown.JWKS())
	mux.Handle("GET /.well-known/openid-configuration", wellKnown.Discovery())

	// The exchange endpoint requires a valid (signature-checked) dauth token from
	// a registered developer license; the body is capped since requests are tiny.
	exchange := httpmw.MaxBytes(maxRequestBytes)(jwtAuth(devLicense(http.HandlerFunc(httpCtrl.ExchangeToken))))
	mux.Handle("POST /v1/tokens/exchange", exchange)

	return httpmw.Recover(logger)(mux), nil
}

// maxRequestBytes caps the exchange request body; the payload is small JSON.
const maxRequestBytes = 1 << 20 // 1 MiB

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
