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
	// Create SGX-protected database for light client
	lightClientDir := cfg.GetLightClientDir()
	db, err := enclave.NewSealedLevelDB("light_client", lightClientDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create light client database: %w", err)
	}

	// Ensure a session nonce exists in the DB, binding sealed files to this DB instance.
	sessionNonce, err := ensureSessionNonce(db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ensure session nonce: %w", err)
	}

	ctx := context.Background()

	// Determine initialization strategy based on DB state, not config values.
	// - If DB has existing light client state (from a previous run): Load from DB.
	// - If DB is empty (first-time startup): Create new instance from config's trusted block.
	hasExistingState, err := story.HasTrustedState(db, cfg.LightClient.ChainID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check existing light client state: %w", err)
	}

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

			queryClient, fallbackErr := fallbackToConfigTrustedBlock(ctx, cfg, db)
			if fallbackErr != nil {
				return nil, nil, fmt.Errorf("failed to resume from DB (%w) and fallback from config also failed: %w", err, fallbackErr)
			}

			// Re-read the nonce because fallbackToConfigTrustedBlock regenerates it.
			sessionNonce, err = ensureSessionNonce(db)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read regenerated session nonce: %w", err)
			}

			return queryClient, sessionNonce, nil
		}

		log.Info("Resumed light client from existing sealed state")

		return queryClient, sessionNonce, nil
	}

	// No existing state — first-time initialization from config.
	// Any pre-existing sealed DKG files from a prior DB session will fail
	// nonce verification at use time, so no explicit file check is needed here.
	qc, err := newQueryClientFromConfig(ctx, cfg, db)
	if err != nil {
		return nil, nil, err
	}

	return qc, sessionNonce, nil
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

// fallbackToConfigTrustedBlock clears expired light client state and re-initializes from config.
// This handles the case where the story-kernel was offline longer than the trusted period (~2 weeks),
// causing the stored light client state to expire.
// If the config's trusted block is also expired, returns an actionable error asking the operator
// to update config.toml with a recent trusted block.
func fallbackToConfigTrustedBlock(ctx context.Context, cfg *config.Config, db cmtdb.DB) (story.QueryClient, error) {
	// Check BEFORE ClearTrustedState to avoid irreversibly destroying valid DB state.
	// After DKG finalization, the light client must only resume from sealed DB.
	if err := rejectConfigFallbackIfDKGKeysExist(cfg); err != nil {
		return nil, err
	}

	if err := story.ClearTrustedState(db, cfg.LightClient.ChainID); err != nil {
		return nil, fmt.Errorf("failed to clear expired light client state: %w", err)
	}

	// Regenerate the session nonce. Re-initializing from config.toml breaks chain
	// identity continuity, so any sealed DKG files from the prior session must not
	// be usable under the new light client state.
	if err := regenerateSessionNonce(db); err != nil {
		return nil, fmt.Errorf("failed to regenerate session nonce: %w", err)
	}

	queryClient, err := newQueryClientFromConfig(ctx, cfg, db)
	if err != nil {
		return nil, fmt.Errorf(
			"config's trusted block (height=%d, hash=%s) is also expired or invalid: %w. Please update trusted_height and trusted_hash in config.toml with a recent block (within the trusted period)",
			cfg.LightClient.TrustedHeight, cfg.LightClient.TrustedHash, err,
		)
	}

	log.Warn("Re-initialized light client from config's trusted block after clearing expired DB state")
	log.Info("Consider updating trusted_height and trusted_hash in config.toml with a more recent block to avoid this on future restarts")

	return queryClient, nil
}

// sessionNonceKey is the LevelDB key for the session nonce stored in the
// light client's sealed database. The __kernel/ prefix avoids collisions
// with CometBFT light client keys (which use lb/{chainID}/ and "size").
// ClearTrustedState's store.Prune(0) only deletes light block keys, so
// this nonce survives DB prune operations.
var sessionNonceKey = []byte("__kernel/session_nonce")

// ensureSessionNonce reads or creates a session nonce in the light client DB.
// The nonce binds all sealed DKG files to this specific DB instance.
// If the DB was re-created (e.g., after deletion), a new nonce is generated
// and any pre-existing sealed DKG files will fail nonce verification at use time.
func ensureSessionNonce(db cmtdb.DB) ([]byte, error) {
	existing, err := db.Get(sessionNonceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read session nonce from DB: %w", err)
	}

	if existing != nil {
		if len(existing) != store.SessionNonceSize {
			return nil, fmt.Errorf("corrupted session nonce in DB: expected %d bytes, got %d",
				store.SessionNonceSize, len(existing))
		}
		return existing, nil
	}

	// No nonce in DB — generate a fresh one.
	nonce := make([]byte, store.SessionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate session nonce: %w", err)
	}

	if err := db.SetSync(sessionNonceKey, nonce); err != nil {
		return nil, fmt.Errorf("failed to persist session nonce to DB: %w", err)
	}

	log.Info("Generated and stored new session nonce in DB")

	return nonce, nil
}

// regenerateSessionNonce replaces the existing session nonce in the DB with a
// fresh random value. This is called when falling back to config.toml for light
// client re-initialization, which breaks chain identity continuity. Any sealed
// DKG files created under the prior nonce will fail verification at use time.
func regenerateSessionNonce(db cmtdb.DB) error {
	nonce := make([]byte, store.SessionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate new session nonce: %w", err)
	}

	if err := db.SetSync(sessionNonceKey, nonce); err != nil {
		return fmt.Errorf("failed to persist regenerated session nonce: %w", err)
	}

	log.Info("Regenerated session nonce for config-based light client re-initialization")

	return nil
}

// rejectConfigFallbackIfDKGKeysExist checks whether any sealed dist_key_share
// files exist. After DKG finalization, the light client must resume from sealed
// DB rather than config.toml to preserve chain identity continuity.
func rejectConfigFallbackIfDKGKeysExist(cfg *config.Config) error {
	hasShares, err := store.HasAnyDistKeyShareInDir(cfg.GetDKGStateDir())
	if err != nil {
		return fmt.Errorf("failed to check for existing DKG key shares: %w", err)
	}

	if hasShares {
		return fmt.Errorf(
			"sealed DKG key shares exist but light client state is missing or expired. "+
				"To recover, remove the DKG state directory (%s) and re-register",
			cfg.GetDKGStateDir(),
		)
	}

	return nil
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

	// Wrap the default SGX sealer with session nonce binding so that all sealed
	// DKG files are tied to the current light client DB instance.
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
