package story

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/light"
	"github.com/cometbft/cometbft/light/provider"
	cmthttp "github.com/cometbft/cometbft/light/provider/http"
	dbs "github.com/cometbft/cometbft/light/store/db"
	"github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/cometbft/cometbft/rpc/client"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	ics23 "github.com/cosmos/ics23/go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/config"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

const (
	// refreshIntervalTime is the interval between background block height cache updates.
	// Story chain has ~2.4s block time, so 3s ensures we stay reasonably fresh
	// without excessive light client updates.
	refreshIntervalTime = 3 * time.Second
)

// This can be implemented by either HTTP client or verified light client.
type QueryClient interface {
	GetDKGNetwork(ctx context.Context, codeCommitmentHex string, round uint32) (*pb.DKGNetwork, error)
	GetAllParticipantDKGRegistrations(ctx context.Context, codeCommitmentHex string, round uint32) ([]*pb.DKGRegistration, error)
	GetLatestActiveDKGNetwork(ctx context.Context) (*pb.DKGNetwork, error)
	VerifyStartBlock(ctx context.Context, startBlockHeight int64, startBlockHash []byte) error
	Close() error
}

// TrustedBlockInfo contains the trusted block information for initializing light client.
type TrustedBlockInfo struct {
	TrustedBlockHeight int64
	TrustedBlockHash   []byte
}

// VerifiedQueryClient is a query client that verifies all responses using light client and Merkle proofs.
type VerifiedQueryClient struct {
	cfg                   *config.Config
	rpcClient             *rpchttp.HTTP
	lightClient           *light.Client
	db                    cmtdb.DB
	mutex                 *sync.Mutex
	cdc                   *codec.ProtoCodec
	cachedLastBlockHeight int64
	cancelFunc            context.CancelFunc
}

// NewVerifiedQueryClient creates a new verified query client with light client.
func NewVerifiedQueryClient(ctx context.Context, cfg *config.Config, info *TrustedBlockInfo, db cmtdb.DB) (*VerifiedQueryClient, error) {
	lcMutex := sync.Mutex{}
	chainID := cfg.LightClient.ChainID
	trustedPeriod := cfg.LightClient.GetTrustedPeriod()

	// Create RPC client
	rpcClient, err := rpchttp.New(cfg.LightClient.RPCAddr, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	// Create primary provider
	primaryProvider, err := cmthttp.New(chainID, cfg.LightClient.PrimaryAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary provider: %w", err)
	}

	// Create witness providers
	var witnessProviders []provider.Provider
	for _, witnessAddr := range cfg.LightClient.WitnessAddrs {
		witness, err := cmthttp.New(chainID, witnessAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create witness provider: %w", err)
		}
		witnessProviders = append(witnessProviders, witness)
	}

	// Create light client store
	store := dbs.New(db, chainID)

	// Create logger
	logger := newCometLogger(cfg)

	// Create light client
	var lc *light.Client
	if info == nil {
		// Load from trusted store
		lc, err = light.NewClientFromTrustedStore(
			chainID,
			trustedPeriod,
			primaryProvider,
			witnessProviders,
			store,
			light.SkippingVerification(light.DefaultTrustLevel),
			light.Logger(logger),
		)
	} else {
		// Create new with trusted block info
		trustOptions := light.TrustOptions{
			Period: trustedPeriod,
			Height: info.TrustedBlockHeight,
			Hash:   info.TrustedBlockHash,
		}
		lc, err = light.NewClient(
			ctx,
			chainID,
			trustOptions,
			primaryProvider,
			witnessProviders,
			store,
			light.SkippingVerification(light.DefaultTrustLevel),
			light.Logger(logger),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	// Create a cancellable context for background goroutines
	bgCtx, cancelFunc := context.WithCancel(context.Background())

	queryClient := &VerifiedQueryClient{
		cfg:         cfg,
		rpcClient:   rpcClient,
		lightClient: lc,
		db:          db,
		mutex:       &lcMutex,
		cdc:         MakeCodec(),
		cancelFunc:  cancelFunc,
	}

	// Initialize last block cache
	if err := queryClient.lastBlockCaching(bgCtx); err != nil {
		cancelFunc()

		return nil, fmt.Errorf("failed to cache last block: %w", err)
	}

	// Start background block caching
	go queryClient.startSchedulingLastBlockCaching(bgCtx)

	log.Infof("Verified query client initialized successfully (trustedPeriod=%s, maxRetries=%d, retryDelay=%s)",
		trustedPeriod, cfg.LightClient.GetMaxBlockWaitRetries(), cfg.LightClient.GetBlockWaitRetryDelay())

	return queryClient, nil
}

// HasTrustedState checks if the sealed LevelDB has existing light client trusted state.
// This is used to determine whether to Load (resume) or New (first-time init) the light client.
// The light client store uses keys prefixed with the chainID to store trusted light blocks.
func HasTrustedState(db cmtdb.DB, chainID string) (bool, error) {
	store := dbs.New(db, chainID)
	lastHeight, err := store.LastLightBlockHeight()
	if err != nil {
		return false, fmt.Errorf("failed to query last light block height: %w", err)
	}

	return lastHeight > 0, nil
}

// ClearTrustedState removes all light blocks from the store.
// This is used when the existing trusted state has expired (beyond the trusted period)
// and needs to be replaced with fresh trusted block info from config.
func ClearTrustedState(db cmtdb.DB, chainID string) error {
	store := dbs.New(db, chainID)

	if err := store.Prune(0); err != nil {
		return fmt.Errorf("failed to prune all light blocks: %w", err)
	}

	log.Info("Cleared all existing light client trusted state from sealed DB")

	return nil
}

// LoadVerifiedQueryClient loads an existing verified query client from trusted store.
func LoadVerifiedQueryClient(ctx context.Context, cfg *config.Config, db cmtdb.DB) (*VerifiedQueryClient, error) {
	return NewVerifiedQueryClient(ctx, cfg, nil, db)
}

// Close closes the query client and releases resources.
func (q *VerifiedQueryClient) Close() error {
	if q.cancelFunc != nil {
		q.cancelFunc()
	}
	if q.db != nil {
		return q.db.Close()
	}

	return nil
}

// GetDKGNetwork retrieves and verifies a DKG network.
func (q *VerifiedQueryClient) GetDKGNetwork(ctx context.Context, codeCommitmentHex string, round uint32) (*pb.DKGNetwork, error) {
	key := GetDKGNetworkKey(codeCommitmentHex, round)

	bz, err := q.getStoreData(ctx, StoreKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get DKG network: %w", err)
	}

	if len(bz) == 0 {
		return nil, fmt.Errorf("DKG network not found for code_commitment %s, round %d", codeCommitmentHex, round)
	}

	// Decode DKGNetwork from protobuf
	var network pb.DKGNetwork
	if err := q.cdc.Unmarshal(bz, &network); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DKG network: %w", err)
	}

	return &network, nil
}

// GetAllParticipantDKGRegistrations returns all DKG registrations that are part of
// the active participant set (VERIFIED or FINALIZED status). Both statuses must be
// included because validators finalize at different times — earlier finalizers
// transition their status from VERIFIED to FINALIZED before later finalizers query.
func (q *VerifiedQueryClient) GetAllParticipantDKGRegistrations(ctx context.Context, codeCommitmentHex string, round uint32) ([]*pb.DKGRegistration, error) {
	// First get the network to know which validators are registered
	network, err := q.GetDKGNetwork(ctx, codeCommitmentHex, round)
	if err != nil {
		return nil, fmt.Errorf("failed to get DKG network: %w", err)
	}

	if len(network.GetActiveValSet()) == 0 {
		return nil, errors.New("no active validators in network")
	}

	// Query each validator's registration individually
	var registrations []*pb.DKGRegistration
	for _, validatorAddr := range network.GetActiveValSet() {
		reg, err := q.getDKGRegistration(ctx, codeCommitmentHex, round, validatorAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get registration for validator %s: %w", validatorAddr, err)
		}

		if reg.GetStatus() == pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED ||
			reg.GetStatus() == pb.DKGRegStatus_DKG_REG_STATUS_FINALIZED {
			registrations = append(registrations, reg)
		}
	}

	if len(registrations) == 0 {
		return nil, errors.New("no participant registrations found")
	}

	return registrations, nil
}

// getDKGRegistration retrieves a single DKG registration.
func (q *VerifiedQueryClient) getDKGRegistration(ctx context.Context, codeCommitmentHex string, round uint32, validatorAddr string) (*pb.DKGRegistration, error) {
	key := GetDKGRegistrationKey(codeCommitmentHex, round, validatorAddr)

	bz, err := q.getStoreData(ctx, StoreKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get DKG registration: %w", err)
	}

	if len(bz) == 0 {
		return nil, errors.New("DKG registration not found")
	}

	// Decode DKGRegistration from protobuf
	var registration pb.DKGRegistration
	if err := q.cdc.Unmarshal(bz, &registration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DKG registration: %w", err)
	}

	return &registration, nil
}

// GetLatestActiveDKGNetwork retrieves and verifies the latest active DKG network.
func (q *VerifiedQueryClient) GetLatestActiveDKGNetwork(ctx context.Context) (*pb.DKGNetwork, error) {
	// First, get the latest active round key
	latestActiveKey := GetLatestActiveRoundKey()

	networkKeyBz, err := q.getStoreData(ctx, StoreKey, latestActiveKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest active round key: %w", err)
	}

	if len(networkKeyBz) == 0 {
		return nil, errors.New("no active DKG network found")
	}

	// The value is a string containing "{code_commitment_hex}_{round}"
	networkKey := string(networkKeyBz)

	// Parse to get code commitment and round
	// Use strings.LastIndex since code_commitment_hex itself may contain underscores
	lastUnderscore := strings.LastIndex(networkKey, "_")
	if lastUnderscore < 0 || lastUnderscore == len(networkKey)-1 {
		return nil, fmt.Errorf("failed to parse network key: %s", networkKey)
	}
	codeCommitmentHex := networkKey[:lastUnderscore]
	var round uint32
	_, err = fmt.Sscanf(networkKey[lastUnderscore+1:], "%d", &round)
	if err != nil {
		return nil, fmt.Errorf("failed to parse round from network key %s: %w", networkKey, err)
	}

	// Now get the actual network
	return q.GetDKGNetwork(ctx, codeCommitmentHex, round)
}

// getStoreData retrieves and verifies data from the store using Merkle proofs.
func (q *VerifiedQueryClient) getStoreData(ctx context.Context, storeKey string, key []byte) ([]byte, error) {
	queryHeight := q.getQueryBlockHeight()

	// Query with proof
	result, err := q.queryWithProof(ctx, storeKey, key, queryHeight)
	if err != nil {
		return nil, err
	}

	// CRITICAL: AppHash for height N is in block N+1's header
	// The proof at height N proves the state, but we need the AppHash from height N+1
	nextHeight := queryHeight + 1
	appHash, err := q.waitAndGetAppHash(ctx, nextHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get AppHash for verification: %w", err)
	}

	// Verify the proof chain
	value := result.Response.Value
	if err := q.verifyProof(result.Response.ProofOps, key, value, appHash, queryHeight, nextHeight); err != nil {
		return nil, err
	}

	log.Debugf("Successfully verified Merkle proof for key: %s at height %d", hex.EncodeToString(key), queryHeight)

	return value, nil
}

// queryWithProof performs an ABCI query with proof.
func (q *VerifiedQueryClient) queryWithProof(ctx context.Context, storeKey string, key []byte, height int64) (*ctypes.ResultABCIQuery, error) {
	option := client.ABCIQueryOptions{
		Prove:  true,
		Height: height,
	}

	path := fmt.Sprintf("/store/%s/key", storeKey)
	result, err := q.rpcClient.ABCIQueryWithOptions(ctx, path, cmtbytes.HexBytes(key), option)
	if err != nil {
		return nil, fmt.Errorf("ABCI query failed: %w", err)
	}

	resp := result.Response
	if resp.IsErr() {
		return nil, fmt.Errorf("error response: code(%v) codespace(%v) log(%v)", resp.Code, resp.Codespace, resp.Log)
	}
	if len(resp.Key) == 0 {
		return nil, errors.New("empty key in response")
	}
	if resp.ProofOps == nil || len(resp.ProofOps.Ops) == 0 {
		return nil, errors.New("no proof ops in response")
	}
	if resp.Height <= 0 {
		return nil, fmt.Errorf("invalid height in response: %d", resp.Height)
	}

	return result, nil
}

// waitAndGetAppHash waits for a block to be available and returns its AppHash.
func (q *VerifiedQueryClient) waitAndGetAppHash(ctx context.Context, height int64) ([]byte, error) {
	var block *cmttypes.LightBlock
	var err error

	maxRetries := q.cfg.LightClient.GetMaxBlockWaitRetries()
	retryDelay := q.cfg.LightClient.GetBlockWaitRetryDelay()

	for i := range maxRetries {
		block, err = q.safeVerifyLightBlockAtHeight(ctx, height)
		if err == nil {
			return block.AppHash.Bytes(), nil
		}

		// If the block is too high, wait and retry
		if errors.Is(err, provider.ErrHeightTooHigh) {
			if i == maxRetries-1 {
				return nil, fmt.Errorf("timeout waiting for block %d after %d retries: %w",
					height, maxRetries, err)
			}
			log.Debugf("Block %d not yet available, waiting... (attempt %d/%d)", height, i+1, maxRetries)
			time.Sleep(retryDelay)

			continue
		}

		// For other errors, fail immediately
		return nil, fmt.Errorf("failed to verify block at height %d: %w", height, err)
	}

	return block.AppHash.Bytes(), nil
}

// verifyProof verifies the proof chain.
func (q *VerifiedQueryClient) verifyProof(proofOps *crypto.ProofOps, key, value, appHash []byte, queryHeight, appHashHeight int64) error {
	// Parse proof operations
	proofs, proofTypes, keys, err := parseProofOps(proofOps)
	if err != nil {
		return err
	}

	// All queries in Cosmos SDK with multi-store architecture require 2-step verification:
	// 1. IAVL/SMT proof: proves key->value in module store
	// 2. Simple proof: proves storeKey->moduleRoot in multi-store (AppHash)
	if len(proofs) != 2 {
		return fmt.Errorf("expected 2 proofs for multi-store verification, got %d", len(proofs))
	}

	// Identify IAVL/SMT and Simple proof indices
	moduleProofIdx, simpleProofIdx := identifyProofIndices(proofTypes)

	// Verify the proof chain
	if err := verifyMultiStoreProof(
		proofs[moduleProofIdx], proofs[simpleProofIdx],
		proofTypes[moduleProofIdx], proofTypes[simpleProofIdx],
		keys[moduleProofIdx], keys[simpleProofIdx],
		key, value, appHash,
	); err != nil {
		return fmt.Errorf("proof verification failed at height %d (AppHash from %d): %w",
			queryHeight, appHashHeight, err)
	}

	return nil
}

// parseProofOps parses ProofOps into individual proofs.
func parseProofOps(proofOps *crypto.ProofOps) ([]*ics23.CommitmentProof, []string, [][]byte, error) {
	var proofs []*ics23.CommitmentProof
	var proofTypes []string
	var keys [][]byte

	for _, op := range proofOps.Ops {
		switch op.Type {
		case "ics23:iavl", "ics23:smt", "ics23:simple":
			var proof ics23.CommitmentProof
			if err := proof.Unmarshal(op.Data); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to unmarshal proof (type=%s): %w", op.Type, err)
			}
			proofs = append(proofs, &proof)
			proofTypes = append(proofTypes, op.Type)
			keys = append(keys, op.Key)
		default:
			return nil, nil, nil, fmt.Errorf("unsupported proof type: %s", op.Type)
		}
	}

	if len(proofs) == 0 {
		return nil, nil, nil, errors.New("no ICS23 proofs found")
	}

	return proofs, proofTypes, keys, nil
}

// Returns: (moduleProofIdx, simpleProofIdx).
func identifyProofIndices(proofTypes []string) (moduleProofIdx, simpleProofIdx int) {
	// Module store proofs are IAVL or SMT
	// Multi-store proofs are Simple (Tendermint)
	for i, proofType := range proofTypes {
		if proofType == "ics23:simple" {
			simpleProofIdx = i
		} else {
			moduleProofIdx = i
		}
	}

	return moduleProofIdx, simpleProofIdx
}

// verifyMultiStoreProof verifies a multi-store proof chain (Module + Simple).
func verifyMultiStoreProof(
	moduleProof, simpleProof *ics23.CommitmentProof,
	moduleType, simpleType string,
	moduleKey, simpleKey, queryKey, value, appHash []byte,
) error {
	// Validate proof structure
	if moduleProof.GetExist() == nil {
		return errors.New("module proof missing ExistProof")
	}
	if simpleProof.GetExist() == nil {
		return errors.New("simple proof missing ExistProof")
	}

	// CRITICAL UNDERSTANDING OF MULTI-STORE PROOFS:
	//
	// In Cosmos SDK multi-store architecture:
	// 1. Simple proof proves: storeKey -> moduleRoot (in the multi-store root = AppHash)
	// 2. Module proof (IAVL/SMT) proves: key -> value (in the module's tree with root = moduleRoot)
	//
	// The connection point is:
	// - simpleProof.GetExist().Value contains the expected moduleRoot
	// - moduleProof must prove key->value under that exact moduleRoot
	//
	// Verification order:
	// 1. Get expected moduleRoot from Simple proof's value
	// 2. Verify module proof with that moduleRoot
	// 3. Verify Simple proof with AppHash

	expectedModuleRoot := simpleProof.GetExist().Value

	// Verify module proof (IAVL/SMT)
	if err := verifyModuleProof(moduleProof, moduleType, moduleKey, queryKey, value, expectedModuleRoot); err != nil {
		return err
	}

	// Verify simple proof
	if err := verifySimpleProof(simpleProof, simpleType, simpleKey, expectedModuleRoot, appHash); err != nil {
		return err
	}

	return nil
}

// This proves that key->value exists in the module store with the given moduleRoot.
func verifyModuleProof(
	moduleProof *ics23.CommitmentProof,
	moduleType string,
	moduleKey, queryKey, value, expectedModuleRoot []byte,
) error {
	// Use module key if provided, otherwise use query key
	proofKey := moduleKey
	if len(proofKey) == 0 {
		proofKey = queryKey
	}

	// Get the proof spec for this module type
	spec := getProofSpec(moduleType)

	// Verify: key->value under expectedModuleRoot
	if !ics23.VerifyMembership(spec, expectedModuleRoot, moduleProof, proofKey, value) {
		// Debug output for troubleshooting
		if calculatedRoot, err := moduleProof.Calculate(); err == nil {
			log.Debugf("  Module calculated root: %x", calculatedRoot)
			log.Debugf("  Expected module root:   %x", expectedModuleRoot)
			log.Debugf("  Roots match: %v", bytes.Equal(calculatedRoot, expectedModuleRoot))
		}

		return errors.New("module proof verification failed: proof does not match expected module root")
	}

	return nil
}

// This proves that storeKey->moduleRoot exists in the multi-store and produces the AppHash.
func verifySimpleProof(
	simpleProof *ics23.CommitmentProof,
	simpleType string,
	storeKey, moduleRoot, appHash []byte,
) error {
	// Get the proof spec for simple proof
	spec := getProofSpec(simpleType)

	// Verify: storeKey->moduleRoot with AppHash
	if !ics23.VerifyMembership(spec, appHash, simpleProof, storeKey, moduleRoot) {
		// Debug output for troubleshooting
		if calculatedAppHash, err := simpleProof.Calculate(); err == nil {
			log.Debugf("  Simple calculated root: %x", calculatedAppHash)
			log.Debugf("  Expected AppHash:       %x", appHash)
			log.Debugf("  Roots match: %v", bytes.Equal(calculatedAppHash, appHash))
		}

		return errors.New("simple proof verification failed: proof does not produce expected AppHash")
	}

	return nil
}

// getProofSpec returns the appropriate ProofSpec for a given proof type.
func getProofSpec(proofType string) *ics23.ProofSpec {
	switch proofType {
	case "ics23:iavl":
		return ics23.IavlSpec
	case "ics23:smt":
		return ics23.SmtSpec
	case "ics23:simple":
		return ics23.TendermintSpec
	default:
		log.Warnf("Unknown proof type: %s, using IavlSpec as fallback", proofType)

		return ics23.IavlSpec
	}
}

// getQueryBlockHeight returns the height to use for queries.
func (q *VerifiedQueryClient) getQueryBlockHeight() int64 {
	height := q.GetCachedLastBlockHeight()
	if height < 1 {
		height = 1
	}

	return height
}

// GetCachedLastBlockHeight returns the cached last block height.
func (q *VerifiedQueryClient) GetCachedLastBlockHeight() int64 {
	return q.cachedLastBlockHeight
}

// lastBlockCaching caches the last block height.
func (q *VerifiedQueryClient) lastBlockCaching(ctx context.Context) error {
	lastHeight, err := q.getLastBlockHeight(ctx)
	if err != nil {
		return fmt.Errorf("failed to refresh last block: %w", err)
	}

	log.Debugf("Refreshed last block height: %d", lastHeight)
	q.cachedLastBlockHeight = lastHeight

	return nil
}

// startSchedulingLastBlockCaching periodically updates the last block cache.
func (q *VerifiedQueryClient) startSchedulingLastBlockCaching(ctx context.Context) {
	ticker := time.NewTicker(refreshIntervalTime)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping background block caching")

			return
		case <-ticker.C:
			if err := q.lastBlockCaching(ctx); err != nil {
				log.Errorf("Failed to cache last block: %v", err)
			}
		}
	}
}

// getLastBlockHeight gets the latest verified block height.
func (q *VerifiedQueryClient) getLastBlockHeight(ctx context.Context) (int64, error) {
	trustedBlock, err := q.safeUpdateLightClient(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to update light client: %w", err)
	}

	if trustedBlock == nil {
		lastHeight, err := q.lightClient.LastTrustedHeight()
		if err != nil {
			return 0, fmt.Errorf("failed to get last trusted height: %w", err)
		}

		return lastHeight, nil
	}

	return trustedBlock.Height, nil
}

// safeUpdateLightClient safely updates the light client (thread-safe).
func (q *VerifiedQueryClient) safeUpdateLightClient(ctx context.Context) (*cmttypes.LightBlock, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	return q.lightClient.Update(ctx, time.Now())
}

// safeVerifyLightBlockAtHeight safely verifies a block at specific height (thread-safe).
func (q *VerifiedQueryClient) safeVerifyLightBlockAtHeight(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	return q.lightClient.VerifyLightBlockAtHeight(ctx, height, time.Now())
}

// VerifyStartBlock verifies that the DKG round's start block exists on the canonical chain.
// This is called at the beginning of GenerateDeals to ensure the DKG round was initiated
// on the canonical chain. The light client must have been initialized with a trusted block
// at or before the start block height.
func (q *VerifiedQueryClient) VerifyStartBlock(ctx context.Context, startBlockHeight int64, startBlockHash []byte) error {
	if startBlockHeight <= 0 {
		return fmt.Errorf("invalid start block height: %d", startBlockHeight)
	}
	if len(startBlockHash) == 0 {
		return errors.New("start block hash is empty")
	}

	block, err := q.safeVerifyLightBlockAtHeight(ctx, startBlockHeight)
	if err != nil {
		return fmt.Errorf("failed to verify start block at height %d: %w", startBlockHeight, err)
	}

	if !bytes.Equal(block.Hash().Bytes(), startBlockHash) {
		return fmt.Errorf("start block hash mismatch at height %d: expected %s, got %s",
			startBlockHeight,
			hex.EncodeToString(startBlockHash),
			hex.EncodeToString(block.Hash().Bytes()))
	}

	log.Debugf("Verified DKG start block: height=%d, hash=%s", startBlockHeight, hex.EncodeToString(startBlockHash))

	return nil
}

// newCometLogger creates a CometBFT logger with appropriate log level.
func newCometLogger(cfg *config.Config) cmtlog.Logger {
	logger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))

	logLevel := strings.ToLower(cfg.LogLevel)
	switch logLevel {
	case "panic", "fatal", "error":
		logger = cmtlog.NewFilter(logger, cmtlog.AllowError())
	case "warn", "warning", "info":
		logger = cmtlog.NewFilter(logger, cmtlog.AllowInfo())
	default: // "debug", "trace"
		logger = cmtlog.NewFilter(logger, cmtlog.AllowDebug())
	}

	return logger
}
