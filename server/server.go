package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/debug"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtlight "github.com/cometbft/cometbft/light"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4/group/edwards25519"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

func Serve(cfg *config.Config) (*grpc.Server, chan error) {
	errCh := make(chan error)

	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(recoveryInterceptor()),
	}

	if cfg.GRPC.TLSEnabled() {
		tlsCreds, err := loadServerTLSCredentials(cfg.GRPC)
		if err != nil {
			log.Fatalf("Failed to load TLS credentials: %v", err)
		}

		serverOpts = append(serverOpts, grpc.Creds(tlsCreds))

		if cfg.GRPC.MTLSEnabled() {
			log.Info("gRPC server TLS enabled with mutual TLS (client certificate required)")
		} else {
			log.Info("gRPC server TLS enabled (server-side only)")
		}
	} else {
		log.Warn("gRPC server running without TLS. Set tls_cert_file and tls_key_file to enable.")
	}

	svr := grpc.NewServer(serverOpts...)

	// Initialize query client and session nonce (bound to the light client DB instance).
	queryClient, sessionNonce, err := initializeQueryClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize query client: %v", err)
	}

	// Register story-kernel service server
	registerAllServices(svr, cfg, queryClient, sessionNonce)

	// Only enable gRPC reflection in debug mode for development/testing.
	// Reflection exposes service metadata and must not be enabled in production.
	if cfg.GRPC.DebugMode {
		log.Warn("gRPC reflection is enabled (debug mode). Do NOT use in production.")
		reflection.Register(svr)
	}

	go runServer(cfg, svr, errCh)

	return svr, errCh
}

func runServer(cfg *config.Config, svr *grpc.Server, errCh chan error) {
	log.Infof("gRPC server is started: %s", cfg.GRPC.ListenAddr)

	lis, err := net.Listen("tcp", cfg.GRPC.ListenAddr)
	if err != nil {
		errCh <- fmt.Errorf("failed to listen port for RPC: %w", err)
	}

	errCh <- svr.Serve(lis)
}

func initializeQueryClient(cfg *config.Config) (story.QueryClient, []byte, error) {
	// Create TEE-sealed database for light client (SGX EGETKEY-derived
	// or TDX vTPM PolicyOR sealing depending on the active backend).
	lightClientDir := cfg.GetLightClientDir()
	db, err := enclave.NewSealedLevelDB("light_client", lightClientDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create light client database: %w", err)
	}

	ctx := context.Background()

	hasExistingState, err := story.HasTrustedState(db, cfg.LightClient.ChainID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check existing light client state: %w", err)
	}

	// If sealed DB has valid light client state, resume from it and use the existing nonce.
	if hasExistingState {
		log.Info("Found existing light client state in sealed DB, resuming...")
		queryClient, err := story.LoadVerifiedQueryClient(ctx, cfg, db)
		if err != nil {
			// Only clear DB state and re-initialize when the error indicates the stored
			// state itself is invalid (expired or bad header). Transient failures such as
			// "connection refused" (RPC not yet up) or config errors (ErrNoWitnesses) must
			// NOT clear the DB — doing so would destroy valid state and cause a boot loop
			// if the config's trusted block is also expired.
			if !isDBStateError(err) {
				return nil, nil, fmt.Errorf("failed to resume light client from DB: %w", err)
			}

			log.Warnf("Light client DB state is invalid, falling back to config's trusted block: %v", err)

			return initFromConfig(ctx, cfg, db)
		}

		log.Info("Resumed light client from existing sealed state")

		nonce, err := readSessionNonce(db)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read session nonce: %w", err)
		}

		return queryClient, nonce, nil
	}

	// No existing light client state — initialize from config.toml.
	return initFromConfig(ctx, cfg, db)
}

// initFromConfig initializes the light client from config.toml with a fresh session nonce.
// Every config-based initialization (first boot, expired DB fallback, etc.) generates a
// new nonce, invalidating any sealed DKG files from a prior session.
func initFromConfig(ctx context.Context, cfg *config.Config, db cmtdb.DB) (story.QueryClient, []byte, error) {
	if err := story.ClearTrustedState(db, cfg.LightClient.ChainID); err != nil {
		return nil, nil, fmt.Errorf("failed to clear light client state: %w", err)
	}

	nonce, err := writeNewSessionNonce(db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write session nonce: %w", err)
	}

	qc, err := newQueryClientFromConfig(ctx, cfg, db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize light client from config: %w", err)
	}

	return qc, nonce, nil
}

// newQueryClientFromConfig creates a new verified query client using config's trusted block info.
func newQueryClientFromConfig(ctx context.Context, cfg *config.Config, db cmtdb.DB) (story.QueryClient, error) {
	// Defense in depth: config validation should already enforce these,
	// but check here too since this is a security-critical path.
	if cfg.LightClient.TrustedHeight == 0 || cfg.LightClient.TrustedHash == "" {
		return nil, errors.New("trusted_height and trusted_hash must be set in config for light client initialization")
	}

	hashBytes, err := hex.DecodeString(cfg.LightClient.TrustedHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode trusted hash: %w", err)
	}

	trustedBlockInfo := &story.TrustedBlockInfo{
		TrustedBlockHeight: cfg.LightClient.TrustedHeight,
		TrustedBlockHash:   hashBytes,
	}

	log.Infof("Initializing light client with trusted block: height=%d, hash=%s",
		trustedBlockInfo.TrustedBlockHeight, cfg.LightClient.TrustedHash)

	queryClient, err := story.NewVerifiedQueryClient(ctx, cfg, trustedBlockInfo, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create new verified query client: %w", err)
	}

	log.Info("Successfully initialized verified query client with light client")

	return queryClient, nil
}

// sessionNonceKey is the LevelDB key for the session nonce stored in the
// light client's sealed database. The __kernel/ prefix avoids collisions
// with CometBFT light client keys (which use lb/{chainID}/ and "size").
// ClearTrustedState's store.Prune(0) only deletes light block keys, so
// this nonce survives DB prune operations.
var sessionNonceKey = []byte("__kernel/session_nonce")

// readSessionNonce reads the existing session nonce from the light client DB.
// Returns an error if the nonce is missing or corrupted.
func readSessionNonce(db cmtdb.DB) ([]byte, error) {
	nonce, err := db.Get(sessionNonceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read session nonce from DB: %w", err)
	}

	if nonce == nil {
		return nil, errors.New("session nonce not found in DB")
	}

	if len(nonce) != store.SessionNonceSize {
		return nil, fmt.Errorf("corrupted session nonce in DB: expected %d bytes, got %d",
			store.SessionNonceSize, len(nonce))
	}

	return nonce, nil
}

// writeNewSessionNonce generates a fresh random session nonce and stores it in the DB,
// replacing any existing nonce. This is called on every config-based light client
// initialization to ensure sealed DKG files from a prior session are invalidated.
func writeNewSessionNonce(db cmtdb.DB) ([]byte, error) {
	nonce := make([]byte, store.SessionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate session nonce: %w", err)
	}

	if err := db.SetSync(sessionNonceKey, nonce); err != nil {
		return nil, fmt.Errorf("failed to persist session nonce to DB: %w", err)
	}

	log.Info("Generated new session nonce")

	return nonce, nil
}

// isDBStateError reports whether err indicates the light client's stored state is
// invalid and must be cleared. Only ErrOldHeaderExpired and ErrInvalidHeader qualify;
// all other errors (e.g. ErrNoWitnesses, connection refused) are transient and the
// DB should be preserved.
func isDBStateError(err error) bool {
	var expiredErr cmtlight.ErrOldHeaderExpired
	if errors.As(err, &expiredErr) {
		return true
	}
	var invalidErr cmtlight.ErrInvalidHeader
	return errors.As(err, &invalidErr)
}

// recoveryInterceptor returns a gRPC unary interceptor that catches panics
// (e.g., from the kyber DKG library) and converts them to Internal errors,
// preventing the entire gRPC server from crashing.
func recoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("recovered from panic in %s: %v\n%s", info.FullMethod, r, debug.Stack())
				resp = nil
				err = status.Errorf(codes.Internal, "internal server error in %s", info.FullMethod)
			}
		}()

		return handler(ctx, req)
	}
}

// loadServerTLSCredentials loads the server certificate/key and optionally the CA
// certificate for client verification (mTLS).
func loadServerTLSCredentials(grpcCfg config.GRPCConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(grpcCfg.TLSCertFile, grpcCfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server tls_cert_file / tls_key_file: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// If CA file is provided, enable mutual TLS by requiring and verifying
	// client certificates against the CA.
	if grpcCfg.TLSCAFile != "" {
		caCert, err := os.ReadFile(grpcCfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read tls_ca_file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from tls_ca_file")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caPool
	}

	return credentials.NewTLS(tlsConfig), nil
}

func registerAllServices(svr *grpc.Server, cfg *config.Config, queryClient story.QueryClient, sessionNonce []byte) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Wrap the default TEE sealer with session nonce binding so that all sealed
	// DKG files are tied to the current light client DB instance. Underlying
	// sealer is backend-specific (SGX EGETKEY or TDX vTPM PolicyOR).
	nonceSealer, err := store.NewNonceBindingSealer(store.NewEnclaveSealer(), sessionNonce)
	if err != nil {
		log.Fatalf("Failed to create nonce-binding sealer: %v", err)
	}

	pb.RegisterKernelServiceServer(svr, &service.DKGServer{
		Cfg:                cfg,
		QueryClient:        queryClient,
		Suite:              suite,
		RoundCtxCache:      store.NewRoundContextCache(),
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
		DistKeyShareCache:  store.NewDistKeyShareCache(),
		DKGStore:           store.NewDKGStoreWithSealer(cfg.GetKeysDir(), cfg.GetDKGStateDir(), suite, nonceSealer),
		PIDCache:           store.NewPIDCache(),
	})
}
