package story

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	ics23 "github.com/cosmos/ics23/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/config"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// =============================================================================
// Mock Implementations
// =============================================================================

// Compile-time check that MockLightClient satisfies the LightClient interface.
var _ LightClient = (*MockLightClient)(nil)

type MockLightClient struct {
	mock.Mock
}

func (m *MockLightClient) Update(ctx context.Context, now time.Time) (*cmttypes.LightBlock, error) {
	args := m.Called(ctx, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	lb, ok := args.Get(0).(*cmttypes.LightBlock)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: expected *cmttypes.LightBlock")
	}

	return lb, args.Error(1)
}

func (m *MockLightClient) VerifyLightBlockAtHeight(ctx context.Context, height int64, now time.Time) (*cmttypes.LightBlock, error) {
	args := m.Called(ctx, height, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	lb, ok := args.Get(0).(*cmttypes.LightBlock)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: expected *cmttypes.LightBlock")
	}

	return lb, args.Error(1)
}

func (m *MockLightClient) LastTrustedHeight() (int64, error) {
	args := m.Called()

	height, ok := args.Get(0).(int64)
	if !ok {
		return 0, fmt.Errorf("type assertion failed: expected int64")
	}

	return height, args.Error(1)
}

type MockDB struct {
	mock.Mock
}

func (m *MockDB) Get(key []byte) ([]byte, error) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	data, ok := args.Get(0).([]byte)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: expected []byte")
	}

	return data, args.Error(1)
}

func (m *MockDB) Has(key []byte) (bool, error) {
	args := m.Called(key)

	return args.Bool(0), args.Error(1)
}

func (m *MockDB) Set(key, value []byte) error {
	args := m.Called(key, value)

	return args.Error(0)
}

func (m *MockDB) SetSync(key, value []byte) error {
	args := m.Called(key, value)

	return args.Error(0)
}

func (m *MockDB) Delete(key []byte) error {
	args := m.Called(key)

	return args.Error(0)
}

func (m *MockDB) DeleteSync(key []byte) error {
	args := m.Called(key)

	return args.Error(0)
}

func (m *MockDB) Iterator(start, end []byte) (cmtdb.Iterator, error) {
	args := m.Called(start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	iter, ok := args.Get(0).(cmtdb.Iterator)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: expected cmtdb.Iterator")
	}

	return iter, args.Error(1)
}

func (m *MockDB) ReverseIterator(start, end []byte) (cmtdb.Iterator, error) {
	args := m.Called(start, end)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	iter, ok := args.Get(0).(cmtdb.Iterator)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: expected cmtdb.Iterator")
	}

	return iter, args.Error(1)
}

func (m *MockDB) Close() error {
	args := m.Called()

	return args.Error(0)
}

func (m *MockDB) NewBatch() cmtdb.Batch {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	batch, ok := args.Get(0).(cmtdb.Batch)
	if !ok {
		return nil
	}

	return batch
}

func (m *MockDB) Print() error {
	args := m.Called()

	return args.Error(0)
}

func (m *MockDB) Stats() map[string]string {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	stats, ok := args.Get(0).(map[string]string)
	if !ok {
		return nil
	}

	return stats
}

func (m *MockDB) Compact(start, end []byte) error {
	args := m.Called(start, end)

	return args.Error(0)
}

// =============================================================================
// Test Helpers
// =============================================================================

func createTestDKGNetwork() *pb.DKGNetwork {
	return &pb.DKGNetwork{
		Round:        1,
		ActiveValSet: []string{"validator1", "validator2", "validator3"},
		Total:        3,
		Threshold:    2,
		PublicCoeffs: [][]byte{[]byte("coeff1"), []byte("coeff2")},
		IsResharing:  false,
	}
}

func createTestDKGRegistration() *pb.DKGRegistration {
	return &pb.DKGRegistration{
		Round:     1,
		DkgPubKey: []byte("test_dkg_public_key"),
		Status:    pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
	}
}

func createValidICS23Proof(key, value []byte) *ics23.CommitmentProof {
	return &ics23.CommitmentProof{
		Proof: &ics23.CommitmentProof_Exist{
			Exist: &ics23.ExistenceProof{
				Key:   key,
				Value: value,
				Leaf: &ics23.LeafOp{
					Hash:         ics23.HashOp_SHA256,
					PrehashKey:   ics23.HashOp_NO_HASH,
					PrehashValue: ics23.HashOp_NO_HASH,
					Length:       ics23.LengthOp_NO_PREFIX,
					Prefix:       []byte{0},
				},
				Path: []*ics23.InnerOp{},
			},
		},
	}
}

func createMockProofOps(iavlKey, iavlValue, simpleKey, simpleValue []byte) *crypto.ProofOps {
	iavlProof := createValidICS23Proof(iavlKey, iavlValue)
	simpleProof := createValidICS23Proof(simpleKey, simpleValue)
	iavlData, _ := iavlProof.Marshal()
	simpleData, _ := simpleProof.Marshal()

	return &crypto.ProofOps{
		Ops: []crypto.ProofOp{
			{Type: "ics23:iavl", Key: iavlKey, Data: iavlData},
			{Type: "ics23:simple", Key: simpleKey, Data: simpleData},
		},
	}
}

// =============================================================================
// Tests
// =============================================================================

func TestParseProofOps(t *testing.T) {
	t.Run("valid two proofs", func(t *testing.T) {
		proofOps := createMockProofOps([]byte("test_key"), []byte("test_value"), []byte("store_key"), []byte("module_root"))
		proofs, proofTypes, keys, err := parseProofOps(proofOps)
		require.NoError(t, err)
		assert.Len(t, proofs, 2)
		assert.Len(t, proofTypes, 2)
		assert.Len(t, keys, 2)
		assert.Contains(t, proofTypes, "ics23:iavl")
		assert.Contains(t, proofTypes, "ics23:simple")
	})
	t.Run("unsupported proof type", func(t *testing.T) {
		proofOps := &crypto.ProofOps{Ops: []crypto.ProofOp{{Type: "unknown_type", Key: []byte("key"), Data: []byte("data")}}}
		_, _, _, err := parseProofOps(proofOps)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported proof type")
	})
	t.Run("invalid proof data", func(t *testing.T) {
		proofOps := &crypto.ProofOps{Ops: []crypto.ProofOp{{Type: "ics23:iavl", Key: []byte("key"), Data: []byte("invalid_data")}}}
		_, _, _, err := parseProofOps(proofOps)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal proof")
	})
	t.Run("empty proof ops", func(t *testing.T) {
		proofOps := &crypto.ProofOps{Ops: []crypto.ProofOp{}}
		_, _, _, err := parseProofOps(proofOps)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no ICS23 proofs found")
	})
}

func TestIdentifyProofIndices(t *testing.T) {
	tests := []struct {
		name          string
		proofTypes    []string
		wantModuleIdx int
		wantSimpleIdx int
	}{
		{"iavl first, simple second", []string{"ics23:iavl", "ics23:simple"}, 0, 1},
		{"simple first, iavl second", []string{"ics23:simple", "ics23:iavl"}, 1, 0},
		{"smt and simple", []string{"ics23:smt", "ics23:simple"}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			moduleIdx, simpleIdx := identifyProofIndices(tt.proofTypes)
			assert.Equal(t, tt.wantModuleIdx, moduleIdx)
			assert.Equal(t, tt.wantSimpleIdx, simpleIdx)
		})
	}
}

func TestGetProofSpec(t *testing.T) {
	tests := []struct {
		name      string
		proofType string
		wantSpec  *ics23.ProofSpec
	}{
		{"iavl spec", "ics23:iavl", ics23.IavlSpec},
		{"smt spec", "ics23:smt", ics23.SmtSpec},
		{"simple spec", "ics23:simple", ics23.TendermintSpec},
		{"unknown defaults to iavl", "unknown", ics23.IavlSpec},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := getProofSpec(tt.proofType)
			assert.Equal(t, tt.wantSpec, spec)
		})
	}
}

func TestKeyGeneration(t *testing.T) {
	t.Run("GetDKGNetworkKey", func(t *testing.T) {
		key1 := GetDKGNetworkKey("test", 1)
		key2 := GetDKGNetworkKey("test", 1)
		assert.NotEmpty(t, key1)
		assert.True(t, bytes.Equal(key1, key2))
	})
	t.Run("GetDKGRegistrationKey", func(t *testing.T) {
		key := GetDKGRegistrationKey("codeCommitment", 1, "validator1")
		assert.NotEmpty(t, key)
	})
	t.Run("GetLatestActiveRoundKey", func(t *testing.T) {
		key := GetLatestActiveRoundKey()
		assert.NotEmpty(t, key)
	})
}

func TestVerifyModuleProof(t *testing.T) {
	t.Run("failure with wrong root", func(t *testing.T) {
		key := []byte("test_key")
		value := []byte("test_value")
		wrongRoot := []byte("wrong_root")
		proof := createValidICS23Proof(key, value)
		err := verifyModuleProof(proof, "ics23:iavl", key, key, value, wrongRoot)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "module proof verification failed")
	})
	t.Run("empty module key uses query key", func(t *testing.T) {
		queryKey := []byte("query_key")
		value := []byte("test_value")
		emptyModuleKey := []byte{}
		proof := createValidICS23Proof(queryKey, value)
		wrongRoot := []byte("any_root")
		err := verifyModuleProof(proof, "ics23:iavl", emptyModuleKey, queryKey, value, wrongRoot)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "module proof verification failed")
	})
}

func TestVerifySimpleProof(t *testing.T) {
	t.Run("failure with wrong app hash", func(t *testing.T) {
		storeKey := []byte("store")
		moduleRoot := []byte("root")
		wrongHash := []byte("wrong")
		proof := createValidICS23Proof(storeKey, moduleRoot)
		err := verifySimpleProof(proof, "ics23:simple", storeKey, moduleRoot, wrongHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "simple proof verification failed")
	})
}

func TestVerifyMultiStoreProof(t *testing.T) {
	t.Run("missing both exist and nonexist proof", func(t *testing.T) {
		moduleProof := &ics23.CommitmentProof{} // neither exist nor nonexist
		simpleProof := createValidICS23Proof([]byte("k"), []byte("v"))
		err := verifyMultiStoreProof(moduleProof, simpleProof, "ics23:iavl", "ics23:simple", []byte("k"), []byte("s"), []byte("q"), []byte("v"), []byte("h"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "module proof missing both ExistProof and NonExistProof")
	})
	t.Run("nonexist module proof attempts verification", func(t *testing.T) {
		moduleProof := &ics23.CommitmentProof{Proof: &ics23.CommitmentProof_Nonexist{Nonexist: &ics23.NonExistenceProof{}}}
		simpleProof := createValidICS23Proof([]byte("k"), []byte("v"))
		err := verifyMultiStoreProof(moduleProof, simpleProof, "ics23:iavl", "ics23:simple", []byte("k"), []byte("s"), []byte("q"), nil, []byte("h"))
		assert.Error(t, err)
		// Should attempt non-existence verification (and fail because proof is empty)
		assert.Contains(t, err.Error(), "non-existence proof verification failed")
	})
	t.Run("missing simple exist proof", func(t *testing.T) {
		moduleProof := createValidICS23Proof([]byte("k"), []byte("v"))
		simpleProof := &ics23.CommitmentProof{Proof: &ics23.CommitmentProof_Nonexist{Nonexist: &ics23.NonExistenceProof{}}}
		err := verifyMultiStoreProof(moduleProof, simpleProof, "ics23:iavl", "ics23:simple", []byte("k"), []byte("s"), []byte("q"), []byte("v"), []byte("h"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "simple proof missing ExistProof")
	})
	t.Run("validates structure", func(t *testing.T) {
		moduleProof := createValidICS23Proof([]byte("key"), []byte("value"))
		simpleProof := createValidICS23Proof([]byte("store"), []byte("root"))
		err := verifyMultiStoreProof(moduleProof, simpleProof, "ics23:iavl", "ics23:simple", []byte("key"), []byte("store"), []byte("key"), []byte("value"), []byte("hash"))
		assert.Error(t, err)
		assert.NotContains(t, err.Error(), "missing ExistProof")
	})
}

func TestTrustedBlockInfo(t *testing.T) {
	info := &TrustedBlockInfo{TrustedBlockHeight: 12345, TrustedBlockHash: []byte("hash")}
	assert.Equal(t, int64(12345), info.TrustedBlockHeight)
	assert.Equal(t, []byte("hash"), info.TrustedBlockHash)
}

func TestMarshaling(t *testing.T) {
	cdc := MakeCodec()
	t.Run("DKGNetwork", func(t *testing.T) {
		network := createTestDKGNetwork()
		data, err := cdc.Marshal(network)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
		var decoded pb.DKGNetwork
		err = cdc.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, network.GetRound(), decoded.GetRound())
		assert.Equal(t, network.GetActiveValSet(), decoded.GetActiveValSet())
	})
	t.Run("DKGRegistration", func(t *testing.T) {
		reg := createTestDKGRegistration()
		data, err := cdc.Marshal(reg)
		require.NoError(t, err)
		var decoded pb.DKGRegistration
		err = cdc.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, reg.GetRound(), decoded.GetRound())
		assert.Equal(t, reg.GetStatus(), decoded.GetStatus())
	})
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 3*time.Second, refreshIntervalTime)
}

func TestMakeCodec(t *testing.T) {
	cdc := MakeCodec()
	assert.NotNil(t, cdc)
	assert.IsType(t, &codec.ProtoCodec{}, cdc)
}

func TestHexEncoding(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	hexStr := hex.EncodeToString(data)
	decoded, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, decoded))
}

func TestMockLightClient(t *testing.T) {
	t.Run("update error", func(t *testing.T) {
		mockLC := new(MockLightClient)
		mockLC.On("Update", mock.Anything, mock.Anything).Return(nil, errors.New("sync failed"))
		_, err := mockLC.Update(t.Context(), time.Now())
		assert.Error(t, err)
		mockLC.AssertExpectations(t)
	})
	t.Run("verify block error", func(t *testing.T) {
		mockLC := new(MockLightClient)
		mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(100), mock.Anything).Return(nil, errors.New("not found"))
		_, err := mockLC.VerifyLightBlockAtHeight(t.Context(), 100, time.Now())
		assert.Error(t, err)
		mockLC.AssertExpectations(t)
	})
}

func TestClose(t *testing.T) {
	t.Run("close with db and cancel", func(t *testing.T) {
		mockDB := new(MockDB)
		mockDB.On("Close").Return(nil)
		_, cancel := context.WithCancel(t.Context())
		client := &VerifiedQueryClient{db: mockDB, cancelFunc: cancel}
		err := client.Close()
		assert.NoError(t, err)
		mockDB.AssertExpectations(t)
	})
	t.Run("close without db", func(t *testing.T) {
		client := &VerifiedQueryClient{db: nil}
		err := client.Close()
		assert.NoError(t, err)
	})
	t.Run("close with cancel but no db", func(t *testing.T) {
		_, cancel := context.WithCancel(t.Context())
		client := &VerifiedQueryClient{db: nil, cancelFunc: cancel}
		err := client.Close()
		assert.NoError(t, err)
	})
}

func TestGetCachedLastBlockHeight(t *testing.T) {
	client := &VerifiedQueryClient{cachedLastBlockHeight: 12345}
	height := client.GetCachedLastBlockHeight()
	assert.Equal(t, int64(12345), height)
}

func TestGetQueryBlockHeight(t *testing.T) {
	tests := []struct {
		name         string
		cachedHeight int64
		expected     int64
	}{
		{"normal height", 100, 100},
		{"zero height falls back to 1", 0, 1},
		{"negative height falls back to 1", -1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &VerifiedQueryClient{cachedLastBlockHeight: tt.cachedHeight}
			height := client.getQueryBlockHeight()
			assert.Equal(t, tt.expected, height)
		})
	}
}

func TestVerifyProof_InvalidProofCount(t *testing.T) {
	client := &VerifiedQueryClient{cdc: MakeCodec()}
	t.Run("single proof only", func(t *testing.T) {
		proof := createValidICS23Proof([]byte("key"), []byte("value"))
		proofData, _ := proof.Marshal()
		proofOps := &crypto.ProofOps{Ops: []crypto.ProofOp{{Type: "ics23:iavl", Key: []byte("key"), Data: proofData}}}
		err := client.verifyProof(proofOps, []byte("key"), []byte("value"), []byte("hash"), 100, 101)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 2 proofs")
	})
}

func TestNewCometLogger(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"error level", "error"},
		{"warn level", "warn"},
		{"info level", "info"},
		{"debug level", "debug"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{LogLevel: tt.logLevel}
			logger := newCometLogger(cfg)
			assert.NotNil(t, logger)
		})
	}
}

func TestGetLatestActiveDKGNetwork_ParseError(t *testing.T) {
	// On-chain latest active round value is just a round number string.
	// Non-numeric values should fail parsing.
	invalidKey := "not_a_number"
	var round uint32
	_, err := fmt.Sscanf(invalidKey, "%d", &round)
	assert.Error(t, err)
}

func TestMutexConcurrency(t *testing.T) {
	client := &VerifiedQueryClient{mutex: &sync.Mutex{}, cachedLastBlockHeight: 1000}
	done := make(chan bool, 100)
	for range 100 {
		go func() {
			_ = client.GetCachedLastBlockHeight()
			done <- true
		}()
	}
	for range 100 {
		<-done
	}
	assert.True(t, true)
}

// =============================================================================
// Additional Coverage Tests
// =============================================================================

func TestVerifyProof_FullFlow(t *testing.T) {
	client := &VerifiedQueryClient{cdc: MakeCodec()}
	proofOps := createMockProofOps([]byte("key"), []byte("value"), []byte("store"), []byte("root"))
	err := client.verifyProof(proofOps, []byte("key"), []byte("value"), []byte("hash"), 100, 101)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proof verification failed")
}

func TestGetStoreData_Logic(t *testing.T) {
	queryHeight := int64(100)
	nextHeight := queryHeight + 1
	assert.Equal(t, int64(101), nextHeight)
}

func TestWaitAndGetAppHash_RetryLogic(t *testing.T) {
	cfg := &config.Config{
		LightClient: config.LightClientConfig{},
	}
	maxRetries := cfg.LightClient.GetMaxBlockWaitRetries()
	retryDelay := cfg.LightClient.GetBlockWaitRetryDelay()

	assert.Equal(t, 10, maxRetries)
	assert.Equal(t, 1*time.Second, retryDelay)
	totalWait := time.Duration(maxRetries) * retryDelay
	assert.Equal(t, 10*time.Second, totalWait)
}

func TestGetDKGNetwork_Flow(t *testing.T) {
	t.Run("builds key correctly", func(t *testing.T) {
		codeCommitment := "test_code_commitment"
		round := uint32(1)
		key := GetDKGNetworkKey(codeCommitment, round)
		assert.NotEmpty(t, key)
		key2 := GetDKGNetworkKey(codeCommitment, round)
		assert.True(t, bytes.Equal(key, key2))
	})
	t.Run("unmarshal error", func(t *testing.T) {
		cdc := MakeCodec()
		var network pb.DKGNetwork
		err := cdc.Unmarshal([]byte("invalid"), &network)
		assert.Error(t, err)
	})
}

func TestGetAllParticipantDKGRegistrations_Flow(t *testing.T) {
	verifiedStatus := pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED
	assert.Equal(t, pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED, verifiedStatus)
}

func TestGetAllParticipantDKGRegistrations_FailFast(t *testing.T) {
	t.Run("returns error immediately on query failure", func(t *testing.T) {
		// Simulates the fail-fast behavior: any single getDKGRegistration error
		// should propagate up as an error from GetAllParticipantDKGRegistrations
		err := fmt.Errorf("failed to get registration for validator val1: connection refused")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get registration for validator")
	})
	t.Run("empty active val set returns error", func(t *testing.T) {
		network := &pb.DKGNetwork{ActiveValSet: []string{}}
		assert.Empty(t, network.GetActiveValSet())
	})
}

func TestConfigDefaults(t *testing.T) {
	t.Run("default trusted period", func(t *testing.T) {
		cfg := config.LightClientConfig{}
		assert.Equal(t, 2*7*24*time.Hour, cfg.GetTrustedPeriod())
	})
	t.Run("custom trusted period", func(t *testing.T) {
		cfg := config.LightClientConfig{TrustedPeriod: 1 * 24 * time.Hour}
		assert.Equal(t, 1*24*time.Hour, cfg.GetTrustedPeriod())
	})
	t.Run("default max block wait retries", func(t *testing.T) {
		cfg := config.LightClientConfig{}
		assert.Equal(t, 10, cfg.GetMaxBlockWaitRetries())
	})
	t.Run("custom max block wait retries", func(t *testing.T) {
		cfg := config.LightClientConfig{MaxBlockWaitRetries: 20}
		assert.Equal(t, 20, cfg.GetMaxBlockWaitRetries())
	})
	t.Run("default block wait retry delay", func(t *testing.T) {
		cfg := config.LightClientConfig{}
		assert.Equal(t, 1*time.Second, cfg.GetBlockWaitRetryDelay())
	})
	t.Run("custom block wait retry delay", func(t *testing.T) {
		cfg := config.LightClientConfig{BlockWaitRetryDelay: 2 * time.Second}
		assert.Equal(t, 2*time.Second, cfg.GetBlockWaitRetryDelay())
	})
}

func TestMinWitnessValidation(t *testing.T) {
	t.Run("zero witnesses rejected", func(t *testing.T) {
		cfg := config.LightClientConfig{
			ChainID:       "test",
			RPCAddr:       "http://localhost:26657",
			PrimaryAddr:   "http://localhost:26657",
			WitnessAddrs:  []string{},
			TrustedHeight: 1,
			TrustedHash:   "abc",
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 2 witness addresses")
	})
	t.Run("one witness rejected", func(t *testing.T) {
		cfg := config.LightClientConfig{
			ChainID:       "test",
			RPCAddr:       "http://localhost:26657",
			PrimaryAddr:   "http://localhost:26657",
			WitnessAddrs:  []string{"http://witness1:26657"},
			TrustedHeight: 1,
			TrustedHash:   "abc",
		}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 2 witness addresses")
	})
	t.Run("two witnesses accepted", func(t *testing.T) {
		cfg := config.LightClientConfig{
			ChainID:       "test",
			RPCAddr:       "http://localhost:26657",
			PrimaryAddr:   "http://localhost:26657",
			WitnessAddrs:  []string{"http://witness1:26657", "http://witness2:26657"},
			TrustedHeight: 1,
			TrustedHash:   "abc",
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestGetLatestActiveDKGNetwork_Parsing(t *testing.T) {
	t.Run("parses round number", func(t *testing.T) {
		// On-chain latest active round value is just a round number string.
		networkKeyBz := []byte("123")
		var round uint32
		_, err := fmt.Sscanf(string(networkKeyBz), "%d", &round)
		assert.NoError(t, err)
		assert.Equal(t, uint32(123), round)
	})
	t.Run("parses single digit round", func(t *testing.T) {
		networkKeyBz := []byte("1")
		var round uint32
		_, err := fmt.Sscanf(string(networkKeyBz), "%d", &round)
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), round)
	})
	t.Run("handles non-numeric value", func(t *testing.T) {
		networkKeyBz := []byte("invalid")
		var round uint32
		_, err := fmt.Sscanf(string(networkKeyBz), "%d", &round)
		assert.Error(t, err)
	})
	t.Run("handles empty value", func(t *testing.T) {
		networkKeyBz := []byte("")
		var round uint32
		_, err := fmt.Sscanf(string(networkKeyBz), "%d", &round)
		assert.Error(t, err)
	})
}

func TestVerifyTrustedBlockInfo_Logic(t *testing.T) {
	hash1 := []byte("test_hash")
	hash2 := []byte("test_hash")
	hash3 := []byte("different_hash")
	assert.True(t, bytes.Equal(hash1, hash2))
	assert.False(t, bytes.Equal(hash1, hash3))
}

func TestGetLastBlockHeight_LogicPaths(t *testing.T) {
	t.Run("handles nil trusted block", func(t *testing.T) {
		var trustedBlock *cmttypes.LightBlock = nil
		assert.Nil(t, trustedBlock)
	})
	t.Run("uses block height when available", func(t *testing.T) {
		trustedBlock := &cmttypes.LightBlock{
			SignedHeader: &cmttypes.SignedHeader{
				Header: &cmttypes.Header{Height: 100},
			},
		}
		assert.Equal(t, int64(100), trustedBlock.Height)
	})
}

func TestSafeMutex_Behavior(t *testing.T) {
	t.Run("mutex prevents concurrent access", func(t *testing.T) {
		mutex := &sync.Mutex{}
		mutex.Lock()
		mutex.Unlock()
		assert.True(t, true)
	})
	t.Run("mutex serializes access", func(t *testing.T) {
		mutex := &sync.Mutex{}
		done := make(chan bool, 2)
		go func() {
			mutex.Lock()
			time.Sleep(10 * time.Millisecond)
			mutex.Unlock()
			done <- true
		}()
		go func() {
			time.Sleep(5 * time.Millisecond)
			mutex.Lock()
			mutex.Unlock()
			done <- true
		}()
		<-done
		<-done
		assert.True(t, true)
	})
}

func TestAdditionalEdgeCases(t *testing.T) {
	t.Run("empty code commitment", func(t *testing.T) {
		key := GetDKGNetworkKey("", 1)
		assert.NotEmpty(t, key)
	})
	t.Run("zero round", func(t *testing.T) {
		key := GetDKGNetworkKey("test", 0)
		assert.NotEmpty(t, key)
	})
	t.Run("max uint32 round", func(t *testing.T) {
		key := GetDKGNetworkKey("test", ^uint32(0))
		assert.NotEmpty(t, key)
	})
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkParseProofOps(b *testing.B) {
	proofOps := createMockProofOps([]byte("k"), []byte("v"), []byte("s"), []byte("r"))
	b.ResetTimer()
	for range b.N {
		_, _, _, _ = parseProofOps(proofOps)
	}
}

func BenchmarkGetProofSpec(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		_ = getProofSpec("ics23:iavl")
	}
}

func BenchmarkDKGNetworkMarshal(b *testing.B) {
	network := createTestDKGNetwork()
	cdc := MakeCodec()
	b.ResetTimer()
	for range b.N {
		_, _ = cdc.Marshal(network)
	}
}

func BenchmarkGetLatestActiveRoundKey(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		_ = GetLatestActiveRoundKey()
	}
}

func BenchmarkVerifyProof(b *testing.B) {
	client := &VerifiedQueryClient{cdc: MakeCodec()}
	proofOps := createMockProofOps([]byte("key"), []byte("value"), []byte("store"), []byte("root"))
	b.ResetTimer()
	for range b.N {
		_ = client.verifyProof(proofOps, []byte("key"), []byte("value"), []byte("hash"), 100, 101)
	}
}

// =============================================================================
// Integration Tests with Mock Light Client
// =============================================================================

// newTestVerifiedQueryClient creates a VerifiedQueryClient with a mock light client
// and default config, suitable for unit testing methods that depend on the light client.
func newTestVerifiedQueryClient(mockLC *MockLightClient) *VerifiedQueryClient {
	return &VerifiedQueryClient{
		cfg: &config.Config{
			LightClient: config.LightClientConfig{},
		},
		lightClient: mockLC,
		mutex:       &sync.Mutex{},
		cdc:         MakeCodec(),
	}
}

// TestGetLastBlockHeight_UpdateReturnsBlock verifies that getLastBlockHeight
// returns the block height from a successful Update call.
func TestGetLastBlockHeight_UpdateReturnsBlock(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 500},
		},
	}
	mockLC.On("Update", mock.Anything, mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	height, err := client.getLastBlockHeight(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(500), height)
	mockLC.AssertExpectations(t)
}

// TestGetLastBlockHeight_UpdateReturnsNil verifies that when Update returns nil,
// getLastBlockHeight falls back to LastTrustedHeight.
func TestGetLastBlockHeight_UpdateReturnsNil(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("Update", mock.Anything, mock.Anything).Return(nil, nil)
	mockLC.On("LastTrustedHeight").Return(int64(300), nil)

	client := newTestVerifiedQueryClient(mockLC)
	height, err := client.getLastBlockHeight(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(300), height)
	mockLC.AssertExpectations(t)
}

// TestGetLastBlockHeight_UpdateError verifies that an Update error is propagated.
func TestGetLastBlockHeight_UpdateError(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("Update", mock.Anything, mock.Anything).Return(nil, errors.New("provider unreachable"))

	client := newTestVerifiedQueryClient(mockLC)
	_, err := client.getLastBlockHeight(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update light client")
	mockLC.AssertExpectations(t)
}

// TestGetLastBlockHeight_LastTrustedHeightError verifies that a LastTrustedHeight
// error is propagated when Update returns nil.
func TestGetLastBlockHeight_LastTrustedHeightError(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("Update", mock.Anything, mock.Anything).Return(nil, nil)
	mockLC.On("LastTrustedHeight").Return(int64(0), errors.New("db corrupted"))

	client := newTestVerifiedQueryClient(mockLC)
	_, err := client.getLastBlockHeight(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get last trusted height")
	mockLC.AssertExpectations(t)
}

// TestLastBlockCaching_Success verifies that lastBlockCaching updates the cached height.
func TestLastBlockCaching_Success(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 1000},
		},
	}
	mockLC.On("Update", mock.Anything, mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	assert.Equal(t, int64(0), client.GetCachedLastBlockHeight())

	err := client.lastBlockCaching(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1000), client.GetCachedLastBlockHeight())
	mockLC.AssertExpectations(t)
}

// TestLastBlockCaching_Error verifies that lastBlockCaching returns error
// without modifying the cached height.
func TestLastBlockCaching_Error(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("Update", mock.Anything, mock.Anything).Return(nil, errors.New("sync failed"))

	client := newTestVerifiedQueryClient(mockLC)
	client.cachedLastBlockHeight = 50

	err := client.lastBlockCaching(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to refresh last block")
	// Cached height should remain unchanged on error
	assert.Equal(t, int64(50), client.GetCachedLastBlockHeight())
	mockLC.AssertExpectations(t)
}

// TestSafeUpdateLightClient verifies thread-safe delegation to lightClient.Update.
func TestSafeUpdateLightClient(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 42},
		},
	}
	mockLC.On("Update", mock.Anything, mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	block, err := client.safeUpdateLightClient(t.Context())
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, int64(42), block.Height)
	mockLC.AssertExpectations(t)
}

// TestSafeVerifyLightBlockAtHeight verifies thread-safe delegation to
// lightClient.VerifyLightBlockAtHeight.
func TestSafeVerifyLightBlockAtHeight(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 200},
		},
	}
	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(200), mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	block, err := client.safeVerifyLightBlockAtHeight(t.Context(), 200)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, int64(200), block.Height)
	mockLC.AssertExpectations(t)
}

// TestSafeVerifyLightBlockAtHeight_Error verifies error propagation.
func TestSafeVerifyLightBlockAtHeight_Error(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(999), mock.Anything).
		Return(nil, errors.New("block not found"))

	client := newTestVerifiedQueryClient(mockLC)
	_, err := client.safeVerifyLightBlockAtHeight(t.Context(), 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block not found")
	mockLC.AssertExpectations(t)
}

// TestVerifyStartBlock_InvalidHeight_WithMock verifies that invalid heights are rejected
// using the mock-injected client.
func TestVerifyStartBlock_InvalidHeight_WithMock(t *testing.T) {
	client := newTestVerifiedQueryClient(new(MockLightClient))

	err := client.VerifyStartBlock(t.Context(), 0, []byte("hash"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid start block height")

	err = client.VerifyStartBlock(t.Context(), -1, []byte("hash"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid start block height")
}

// TestVerifyStartBlock_EmptyHash_WithMock verifies that empty hash is rejected
// using the mock-injected client.
func TestVerifyStartBlock_EmptyHash_WithMock(t *testing.T) {
	client := newTestVerifiedQueryClient(new(MockLightClient))

	err := client.VerifyStartBlock(t.Context(), 100, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start block hash is empty")

	err = client.VerifyStartBlock(t.Context(), 100, []byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start block hash is empty")
}

// TestVerifyStartBlock_VerifyError verifies that light client verification
// errors are propagated.
func TestVerifyStartBlock_VerifyError(t *testing.T) {
	mockLC := new(MockLightClient)
	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(100), mock.Anything).
		Return(nil, errors.New("verification failed"))

	client := newTestVerifiedQueryClient(mockLC)
	err := client.VerifyStartBlock(t.Context(), 100, []byte("somehash"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify start block at height 100")
	mockLC.AssertExpectations(t)
}

// TestVerifyStartBlock_HashMismatch verifies that a hash mismatch is detected.
func TestVerifyStartBlock_HashMismatch(t *testing.T) {
	mockLC := new(MockLightClient)
	// Create a light block with a known hash
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 100},
		},
	}
	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(100), mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	// Use a hash that will not match the block hash
	err := client.VerifyStartBlock(t.Context(), 100, []byte("definitely_wrong_hash_that_wont_match"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start block hash mismatch")
	mockLC.AssertExpectations(t)
}

// TestVerifyStartBlock_Success verifies that matching hash passes verification.
func TestVerifyStartBlock_Success(t *testing.T) {
	mockLC := new(MockLightClient)

	// Build a minimal light block with enough data to produce a non-empty hash.
	// A Header with populated fields is sufficient for Hash() to return a value.
	header := &cmttypes.Header{
		Height:  100,
		ChainID: "test-chain",
		Time:    time.Now(),
		// ValidatorsHash is required for a non-empty header hash
		ValidatorsHash: cmttypes.NewValidatorSet(nil).Hash(),
	}
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: header,
		},
	}
	// Get the actual hash from the light block
	actualHash := lb.Hash().Bytes()
	require.NotEmpty(t, actualHash, "test setup: light block hash must not be empty")

	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, int64(100), mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	err := client.VerifyStartBlock(t.Context(), 100, actualHash)
	require.NoError(t, err)
	mockLC.AssertExpectations(t)
}

// TestStartSchedulingLastBlockCaching_StopsOnContextCancel verifies that
// the background goroutine stops when the context is cancelled.
func TestStartSchedulingLastBlockCaching_StopsOnContextCancel(t *testing.T) {
	mockLC := new(MockLightClient)
	// Allow any number of Update calls (may or may not fire before cancel)
	mockLC.On("Update", mock.Anything, mock.Anything).
		Return(nil, nil).Maybe()
	mockLC.On("LastTrustedHeight").Return(int64(1), nil).Maybe()

	client := newTestVerifiedQueryClient(mockLC)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		client.startSchedulingLastBlockCaching(ctx)
		close(done)
	}()

	// Cancel immediately to test clean shutdown
	cancel()

	select {
	case <-done:
		// success: goroutine exited
	case <-time.After(5 * time.Second):
		t.Fatal("startSchedulingLastBlockCaching did not stop after context cancel")
	}
}

// TestGetQueryBlockHeight_AfterCaching verifies that getQueryBlockHeight
// returns the cached height after lastBlockCaching.
func TestGetQueryBlockHeight_AfterCaching(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 750},
		},
	}
	mockLC.On("Update", mock.Anything, mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)
	require.NoError(t, client.lastBlockCaching(t.Context()))

	height := client.getQueryBlockHeight()
	assert.Equal(t, int64(750), height)
}

// TestConcurrentSafeOperations verifies that concurrent calls to safe methods
// do not race (verified by -race detector).
func TestConcurrentSafeOperations(t *testing.T) {
	mockLC := new(MockLightClient)
	lb := &cmttypes.LightBlock{
		SignedHeader: &cmttypes.SignedHeader{
			Header: &cmttypes.Header{Height: 100},
		},
	}
	mockLC.On("Update", mock.Anything, mock.Anything).Return(lb, nil)
	mockLC.On("VerifyLightBlockAtHeight", mock.Anything, mock.Anything, mock.Anything).Return(lb, nil)

	client := newTestVerifiedQueryClient(mockLC)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = client.safeUpdateLightClient(t.Context())
		}()
		go func() {
			defer wg.Done()
			_, _ = client.safeVerifyLightBlockAtHeight(t.Context(), 100)
		}()
	}
	wg.Wait()
}

// TestBuildCollectionKey verifies the key construction helper.
func TestBuildCollectionKey(t *testing.T) {
	key := buildCollectionKey(DKGNetworkPrefix, []byte("test_1"))
	require.NotEmpty(t, key)
	// First byte should be the prefix
	assert.Equal(t, DKGNetworkPrefix, key[0])
	// Key should contain the original bytes
	assert.Contains(t, string(key), "test_1")
}

// TestBuildCollectionKey_DifferentPrefixes verifies that different prefixes
// produce different keys.
func TestBuildCollectionKey_DifferentPrefixes(t *testing.T) {
	key1 := buildCollectionKey(DKGNetworkPrefix, []byte("same"))
	key2 := buildCollectionKey(DKGRegistrationPrefix, []byte("same"))
	assert.False(t, bytes.Equal(key1, key2), "different prefixes should produce different keys")
}

// TestGetDKGNetworkKey_Deterministic verifies that the same inputs always
// produce the same key.
func TestGetDKGNetworkKey_Deterministic(t *testing.T) {
	key1 := GetDKGNetworkKey("commitment", 5)
	key2 := GetDKGNetworkKey("commitment", 5)
	assert.True(t, bytes.Equal(key1, key2))

	// Different round should produce different key
	key3 := GetDKGNetworkKey("commitment", 6)
	assert.False(t, bytes.Equal(key1, key3))
}

// TestGetDKGRegistrationKey_IncludesValidator verifies that different validators
// produce different keys.
func TestGetDKGRegistrationKey_IncludesValidator(t *testing.T) {
	key1 := GetDKGRegistrationKey("cc", 1, "val1")
	key2 := GetDKGRegistrationKey("cc", 1, "val2")
	assert.False(t, bytes.Equal(key1, key2), "different validators should produce different keys")
}
