package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	cmtdb "github.com/cometbft/cometbft-db"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4/group/edwards25519"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func Serve(cfg *config.Config) (*grpc.Server, chan error) {
	errCh := make(chan error)
	svr := grpc.NewServer()

	// Initialize query client
	queryClient, err := initializeQueryClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize query client: %v", err)
	}

	// Register TEE service server
	registerAllServices(svr, cfg, queryClient)

	// TODO: temporarily add reflection for test. Need to remove this in production
	reflection.Register(svr)

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

func initializeQueryClient(cfg *config.Config) (story.QueryClient, error) {
	// Create SGX-protected database for light client
	lightClientDir := cfg.GetLightClientDir()
	db, err := enclave.NewSealedLevelDB("light_client", lightClientDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client database: %w", err)
	}

	ctx := context.Background()

	// Determine initialization strategy based on DB state, not config values.
	// - If DB has existing light client state (from a previous run): Load from DB.
	// - If DB is empty (first-time startup): Create new instance from config's trusted block.
	hasExistingState, err := story.HasTrustedState(db, cfg.LightClient.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing light client state: %w", err)
	}

	if hasExistingState {
		log.Info("Found existing light client state in sealed DB, resuming...")
		queryClient, err := story.LoadVerifiedQueryClient(ctx, cfg, db)
		if err != nil {
			// Existing state likely expired (beyond trusted period).
			// Attempt recovery by falling back to config's trusted block info.
			log.Warnf("Failed to resume light client from DB (possibly expired): %v", err)
			log.Info("Falling back to config's trusted block after clearing expired DB state")

			queryClient, fallbackErr := fallbackToConfigTrustedBlock(ctx, cfg, db)
			if fallbackErr != nil {
				return nil, fmt.Errorf("failed to resume from DB (%w) and fallback from config also failed: %w", err, fallbackErr)
			}

			return queryClient, nil
		}

		log.Info("Resumed light client from existing sealed state")

		return queryClient, nil
	}

	// No existing state — first-time initialization from config.
	return newQueryClientFromConfig(ctx, cfg, db)
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
// This handles the case where the TEE was offline longer than the trusted period (~2 weeks),
// causing the stored light client state to expire.
// If the config's trusted block is also expired, returns an actionable error asking the operator
// to update config.toml with a recent trusted block.
func fallbackToConfigTrustedBlock(ctx context.Context, cfg *config.Config, db cmtdb.DB) (story.QueryClient, error) {
	if err := story.ClearTrustedState(db, cfg.LightClient.ChainID); err != nil {
		return nil, fmt.Errorf("failed to clear expired light client state: %w", err)
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

func registerAllServices(svr *grpc.Server, cfg *config.Config, queryClient story.QueryClient) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pb.RegisterTEEServiceServer(svr, &service.DKGServer{
		Cfg:                cfg,
		QueryClient:        queryClient,
		Suite:              suite,
		RoundCtxCache:      store.NewRoundContextCache(),
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
		DistKeyShareCache:  store.NewDistKeyShareCache(),
		DKGStore:           store.NewDKGStore(cfg.GetKeysDir(), cfg.GetDKGStateDir(), suite),
		PIDCache:           store.NewPIDCache(),
	})
}
