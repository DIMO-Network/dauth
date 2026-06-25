package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/DIMO-Network/dauth/internal/exchange/config"
	"github.com/DIMO-Network/dauth/internal/exchange/contracts/sacd"
	"github.com/DIMO-Network/dauth/internal/exchange/contracts/template"
	"github.com/DIMO-Network/dauth/internal/exchange/controllers/httpcontroller"
	"github.com/DIMO-Network/dauth/internal/exchange/controllers/rpc"
	_ "github.com/DIMO-Network/dauth/internal/exchange/docs" // registers the generated OpenAPI spec
	"github.com/DIMO-Network/dauth/internal/exchange/middleware"
	"github.com/DIMO-Network/dauth/internal/exchange/services"
	"github.com/DIMO-Network/dauth/internal/exchange/services/access"
	"github.com/DIMO-Network/dauth/internal/exchange/services/sacdproxy"
	templatesvs "github.com/DIMO-Network/dauth/internal/exchange/services/template"
	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
	txgrpc "github.com/DIMO-Network/dauth/pkg/grpc"
	"github.com/ethereum/go-ethereum/ethclient"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateServers creates the HTTP handler and gRPC server for the exchange
// (/exchange) surface. The returned handler has routes relative to its mount
// point and no panic recoverer — the merged binary mounts it under /exchange
// and wraps both surfaces with Recover once. jwksURI is the externally reachable
// URL where this surface's keys are published (e.g.
// https://dauth.dimo.zone/exchange/keys), which is advertised in the
// discovery document independently of the iss claim. jwtAuth is the inbound
// sign-in-token validator (built from the /siwe keyset by the caller).
func CreateServers(logger zerolog.Logger, cfg *config.Config, jwksURI string, jwtAuth func(http.Handler) http.Handler) (http.Handler, *grpc.Server, error) {
	keys, err := keyset.Load(config.SigningKeys())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load signing keys: %w", err)
	}
	ttl := 10 * time.Minute
	if cfg.TokenExpiration != "" {
		ttl, err = time.ParseDuration(cfg.TokenExpiration)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid TOKEN_EXPIRATION %q: %w", cfg.TokenExpiration, err)
		}
	}
	signer := services.NewTokenSigner(keys, cfg.Issuer, ttl)

	ethClient, err := ethclient.Dial(cfg.BlockchainNodeURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial Ethereum RPC: %w", err)
	}

	ipfsService, err := services.NewIPFSClient(&logger, cfg.IPFSBaseURL, cfg.IPFSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IPFS client: %w", err)
	}

	sacdContract, err := sacd.NewSacd(cfg.ContractAddressSacd, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	prox := &sacdproxy.Proxy{
		HTTP: &http.Client{
			Timeout: 5 * time.Second, // TODO(elffjs): Configurable?
		},
		QueryEndpoint:          cfg.IdentityURL,
		Contract:               sacdContract,
		ContractAddressVehicle: cfg.ContractAddressVehicle,
	}

	templateContract, err := template.NewTemplate(cfg.ContractAddressTemplate, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to blockchain node: %w", err)
	}

	templateService, err := templatesvs.NewTemplateService(templateContract, ipfsService, ethClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create template service: %w", err)
	}

	accessService, err := access.NewAccessService(ipfsService, prox, templateService, ethClient, cfg.ContractAddressManufacturer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create access service: %w", err)
	}

	handler, err := createHTTPServer(logger, cfg, keys, signer, accessService, jwksURI, jwtAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create http server: %w", err)
	}

	grpcServer := createGRPCServer(rpc.NewTokenExchangeServer(accessService))

	return handler, grpcServer, nil
}

func createHTTPServer(logger zerolog.Logger, cfg *config.Config, keys *keyset.KeySet, signer *services.TokenSigner, accessService *access.Service, jwksURI string, jwtAuth func(http.Handler) http.Handler) (http.Handler, error) {
	httpCtrl, err := httpcontroller.NewExchangeController(cfg, signer, accessService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize exchange controller: %w", err)
	}
	idSvc := services.NewIdentityController(&logger, cfg)
	devLicense := middleware.NewDevLicenseValidator(idSvc, logger)

	wellKnown, err := oidc.NewWellKnown(oidc.Config{
		Issuer:          cfg.Issuer,
		JWKSURI:         jwksURI,
		Keys:            keys,
		ClaimsSupported: []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "asset", "permissions", "cloud_events"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to render well-known surface: %w", err)
	}

	// Routes are relative to the /exchange mount point. The root health check
	// and panic recoverer live at the top level of the merged binary.
	mux := http.NewServeMux()

	// Interactive OpenAPI docs, served over net/http (replaces the Fiber
	// swagger handler; the generated spec is unchanged).
	mux.Handle("GET /swagger/", httpSwagger.WrapHandler)

	// This surface signs permission tokens with its own keyset and publishes the
	// public halves here, taking over the JWKS endpoint DEX used to serve.
	mux.Handle("GET /keys", wellKnown.JWKS())
	mux.Handle("GET /.well-known/jwks.json", wellKnown.JWKS())
	mux.Handle("GET /.well-known/openid-configuration", wellKnown.Discovery())

	// The exchange endpoint requires a valid (signature-checked) sign-in token
	// from a registered developer license; the body is capped since requests are
	// tiny.
	exchange := httpmw.MaxBytes(maxRequestBytes)(jwtAuth(devLicense(http.HandlerFunc(httpCtrl.ExchangeToken))))
	mux.Handle("POST /tokens/exchange", exchange)

	return mux, nil
}

// maxRequestBytes caps the exchange request body; the payload is small JSON.
const maxRequestBytes = 1 << 20 // 1 MiB

func createGRPCServer(rpcCtrl *rpc.TokenExchangeServer) *grpc.Server {
	recoverPanic := func(p any) error {
		return status.Errorf(codes.Internal, "panic: %v", p)
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(recoverPanic)),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)
	txgrpc.RegisterTokenExchangeServiceServer(server, rpcCtrl)
	return server
}
