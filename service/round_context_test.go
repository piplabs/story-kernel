package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// stubQueryClient returns scripted responses per call; tests simulate light-client lag.
// If netErr/regErr is set, that error is returned instead.
type stubQueryClient struct {
	networks      []*pb.DKGNetwork
	registrations [][]*pb.DKGRegistration
	// allRegistrations, when set, is returned by GetAllRegisteredDKGRegistrations
	// (ALL statuses). If nil, that method falls back to the VERIFIED-only set so
	// existing tests keep both sets identical.
	allRegistrations []*pb.DKGRegistration
	netCalls         atomic.Int32
	regCalls         atomic.Int32
	netErr           error
	regErr           error
}

var _ story.QueryClient = (*stubQueryClient)(nil)

func (s *stubQueryClient) GetDKGNetwork(_ context.Context, _ string, _ uint32) (*pb.DKGNetwork, error) {
	i := int(s.netCalls.Add(1)) - 1
	if s.netErr != nil {
		return nil, s.netErr
	}
	if i >= len(s.networks) {
		i = len(s.networks) - 1
	}
	return s.networks[i], nil
}

func (s *stubQueryClient) GetAllParticipantDKGRegistrations(_ context.Context, _ string, _ uint32) ([]*pb.DKGRegistration, error) {
	i := int(s.regCalls.Add(1)) - 1
	if s.regErr != nil {
		return nil, s.regErr
	}
	if i >= len(s.registrations) {
		i = len(s.registrations) - 1
	}
	return s.registrations[i], nil
}

func (s *stubQueryClient) GetAllRegisteredDKGRegistrations(ctx context.Context, cc string, round uint32) ([]*pb.DKGRegistration, error) {
	if s.allRegistrations != nil {
		return s.allRegistrations, nil
	}
	return s.GetAllParticipantDKGRegistrations(ctx, cc, round)
}

// Unused interface methods — panic loudly if accidentally invoked.
func (*stubQueryClient) GetLatestActiveDKGNetwork(_ context.Context) (*pb.DKGNetwork, error) {
	panic("stubQueryClient.GetLatestActiveDKGNetwork: not implemented for round_context tests")
}
func (*stubQueryClient) HasDecryptRequest(_ context.Context, _ uint32, _, _, _ string) (bool, error) {
	panic("stubQueryClient.HasDecryptRequest: not implemented for round_context tests")
}
func (*stubQueryClient) VerifyStartBlock(_ context.Context, _ int64, _ []byte) error {
	panic("stubQueryClient.VerifyStartBlock: not implemented for round_context tests")
}
func (*stubQueryClient) Close() error { return nil }

func TestValidateRegistrations_Valid(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 5}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb"},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc"},
	}

	err := validateRegistrations(regs, network, 5)
	require.NoError(t, err)
}

func TestValidateRegistrations_CountMismatch(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 5, Round: 1}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 1, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 1, ValidatorAddr: "0xbbb"},
	}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration count 2 does not match network total 5")
}

func TestValidateRegistrations_DuplicateIndex(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 1}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 1, ValidatorAddr: "0xaaa"},
		{Index: 1, Round: 1, ValidatorAddr: "0xbbb"}, // duplicate
		{Index: 3, Round: 1, ValidatorAddr: "0xccc"},
	}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate registration index 1")
}

func TestValidateRegistrations_WrongRound(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 2, Round: 5}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 3, ValidatorAddr: "0xbbb"}, // wrong round
	}

	err := validateRegistrations(regs, network, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration round 3 does not match requested round 5")
	assert.Contains(t, err.Error(), "0xbbb")
}

func TestValidateRegistrations_EmptyRegistrations(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 3, Round: 1}
	regs := []*pb.DKGRegistration{}

	err := validateRegistrations(regs, network, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration count 0 does not match network total 3")
}

func TestValidateRegistrations_TotalZero(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 0, Round: 1}
	regs := []*pb.DKGRegistration{}

	// Zero registrations with zero total should pass.
	err := validateRegistrations(regs, network, 1)
	require.NoError(t, err)
}

func TestValidateRegistrations_SingleRegistration(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 1, Round: 10}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 10, ValidatorAddr: "0xaaa"},
	}

	err := validateRegistrations(regs, network, 10)
	require.NoError(t, err)
}

func TestValidateRegistrations_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		network     *pb.DKGNetwork
		regs        []*pb.DKGRegistration
		round       uint32
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid 3 of 3",
			network: &pb.DKGNetwork{Total: 3, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
				{Index: 2, Round: 1},
				{Index: 3, Round: 1},
			},
			round:   1,
			wantErr: false,
		},
		{
			name:    "count mismatch (fewer regs)",
			network: &pb.DKGNetwork{Total: 3, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "registration count",
		},
		{
			name:    "count mismatch (more regs)",
			network: &pb.DKGNetwork{Total: 1, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 1},
				{Index: 2, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "registration count",
		},
		{
			name:    "duplicate index",
			network: &pb.DKGNetwork{Total: 2, Round: 1},
			regs: []*pb.DKGRegistration{
				{Index: 5, Round: 1},
				{Index: 5, Round: 1},
			},
			round:       1,
			wantErr:     true,
			errContains: "duplicate registration index",
		},
		{
			name:    "wrong round on first registration",
			network: &pb.DKGNetwork{Total: 1, Round: 10},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 99},
			},
			round:       10,
			wantErr:     true,
			errContains: "registration round 99 does not match requested round 10",
		},
		{
			name:    "wrong round on second registration",
			network: &pb.DKGNetwork{Total: 2, Round: 5},
			regs: []*pb.DKGRegistration{
				{Index: 1, Round: 5},
				{Index: 2, Round: 7},
			},
			round:       5,
			wantErr:     true,
			errContains: "registration round 7 does not match requested round 5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateRegistrations(tc.regs, tc.network, tc.round)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- ErrLightClientLag sentinel and retry behavior (issue piplabs/story#826) ---

// Total=0 + non-empty regs surfaces ErrLightClientLag so callers can retry.
func TestValidateRegistrations_LagSentinel(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 0, Round: 5}
	regs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb"},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc"},
	}

	err := validateRegistrations(regs, network, 5)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLightClientLag)
	assert.Contains(t, err.Error(), "3 registrations visible but network.Total=0")
}

// Genuinely empty (registration phase not yet observed) is NOT flagged as lag.
func TestValidateRegistrations_TotalZeroEmptyRegs_NotLag(t *testing.T) {
	t.Parallel()

	network := &pb.DKGNetwork{Total: 0, Round: 1}
	err := validateRegistrations(nil, network, 1)
	require.NoError(t, err)
}

// First fetch sees Total=0 (lag) → retry → second fetch succeeds.
func TestGetOrLoadRoundContext_RetriesOnLag(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Build three valid Ed25519 public keys for the post-lag registrations.
	// Deterministic per-index scalars keep the test stable.
	pubKeyBytes := make([][]byte, 3)
	for i := range pubKeyBytes {
		scalar := suite.Scalar().SetInt64(int64(i + 1))
		point := suite.Point().Mul(scalar, nil)
		b, err := point.MarshalBinary()
		require.NoError(t, err)
		pubKeyBytes[i] = b
	}

	validRegs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa", DkgPubKey: pubKeyBytes[0]},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb", DkgPubKey: pubKeyBytes[1]},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc", DkgPubKey: pubKeyBytes[2]},
	}

	stub := &stubQueryClient{
		networks: []*pb.DKGNetwork{
			{Total: 0, Threshold: 0, Round: 5}, // call 1: lag
			{Total: 3, Threshold: 2, Round: 5}, // call 2: caught up
		},
		registrations: [][]*pb.DKGRegistration{
			validRegs,
			validRegs,
		},
	}

	s := &DKGServer{
		QueryClient:   stub,
		Suite:         suite,
		RoundCtxCache: store.NewRoundContextCache(),
	}

	rc, err := s.GetOrLoadRoundContext("cc", 5)
	require.NoError(t, err)
	require.NotNil(t, rc)
	require.Equal(t, uint32(3), rc.Network.GetTotal())
	require.Equal(t, uint32(2), rc.Network.GetThreshold())
	require.Equal(t, int32(2), stub.netCalls.Load(), "initial + 1 retry")
}

// Threshold==0 (no validation error, but stale) also triggers retry.
func TestGetOrLoadRoundContext_RetriesOnZeroThreshold(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Total=0 AND empty regs is the "before registration phase" state — no lag
	// signature in validateRegistrations, but Threshold=0 still triggers retry.
	pre := &pb.DKGNetwork{Total: 0, Threshold: 0, Round: 5}
	post := &pb.DKGNetwork{Total: 1, Threshold: 1, Round: 5}

	point := suite.Point().Mul(suite.Scalar().SetInt64(1), nil)
	pkBytes, err := point.MarshalBinary()
	require.NoError(t, err)
	postReg := []*pb.DKGRegistration{{Index: 1, Round: 5, ValidatorAddr: "0x1", DkgPubKey: pkBytes}}

	stub := &stubQueryClient{
		networks:      []*pb.DKGNetwork{pre, post},
		registrations: [][]*pb.DKGRegistration{{}, postReg},
	}

	s := &DKGServer{
		QueryClient:   stub,
		Suite:         suite,
		RoundCtxCache: store.NewRoundContextCache(),
	}

	rc, err := s.GetOrLoadRoundContext("cc", 5)
	require.NoError(t, err)
	require.Equal(t, uint32(1), rc.Network.GetThreshold(),
		"must retry until Threshold becomes non-zero")
}

// Retry exhaustion preserves ErrLightClientLag in the wrap chain.
func TestGetOrLoadRoundContext_RetryExhaustedOnLag(t *testing.T) {

	// All calls return lag.
	lagRegs := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa"},
	}

	stub := &stubQueryClient{
		networks:      []*pb.DKGNetwork{{Total: 0, Round: 5}},
		registrations: [][]*pb.DKGRegistration{lagRegs},
	}

	s := &DKGServer{
		QueryClient:   stub,
		Suite:         edwards25519.NewBlakeSHA256Ed25519(),
		RoundCtxCache: store.NewRoundContextCache(),
	}

	rc, err := s.GetOrLoadRoundContext("cc", 5)
	require.Error(t, err)
	require.Nil(t, rc)
	require.ErrorIs(t, err, ErrLightClientLag)
	require.Equal(t, int32(thresholdRetryAttempts+1), stub.netCalls.Load(), "initial + N retries")
}

// Non-lag fetch errors bail immediately; the retry loop must not run.
func TestGetOrLoadRoundContext_NonLagFetchErrorAborts(t *testing.T) {

	transportErr := errors.New("rpc: unavailable")
	stub := &stubQueryClient{netErr: transportErr}

	s := &DKGServer{
		QueryClient:   stub,
		Suite:         edwards25519.NewBlakeSHA256Ed25519(),
		RoundCtxCache: store.NewRoundContextCache(),
	}

	rc, err := s.GetOrLoadRoundContext("cc", 5)
	require.Error(t, err)
	require.Nil(t, rc)
	require.ErrorIs(t, err, transportErr)
	require.Equal(t, int32(1), stub.netCalls.Load(), "no retry on non-lag error")
}

// The initial-round kyber node list must preserve an invalidated member's slot.
// A member invalidated mid-dealing is dropped from the VERIFIED-only set but kept
// in the ALL-status set. Because extractSortedPubKeys assigns kyber positions as a
// dense index after sorting by reg.Index, the node list must be built from the
// ALL-status set so a late builder gets the same length and per-position keys as an
// early builder (and as the all-verified case). Without this fix, dropping index 2
// would shift index 3 into position 1, diverging late builders from peers.
func TestFetchRoundContext_PreservesInvalidatedSlot(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Three distinct, deterministic Ed25519 public keys, one per slot.
	pubKeyBytes := make([][]byte, 3)
	for i := range pubKeyBytes {
		point := suite.Point().Mul(suite.Scalar().SetInt64(int64(i+1)), nil)
		b, err := point.MarshalBinary()
		require.NoError(t, err)
		pubKeyBytes[i] = b
	}

	// Baseline: all three verified. network.Total counts the verified set.
	allVerified := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa", DkgPubKey: pubKeyBytes[0], Status: pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb", DkgPubKey: pubKeyBytes[1], Status: pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc", DkgPubKey: pubKeyBytes[2], Status: pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED},
	}

	baseStub := &stubQueryClient{
		networks:      []*pb.DKGNetwork{{Total: 3, Threshold: 2, Round: 5}},
		registrations: [][]*pb.DKGRegistration{allVerified},
	}
	baseSrv := &DKGServer{
		QueryClient:   baseStub,
		Suite:         suite,
		RoundCtxCache: store.NewRoundContextCache(),
	}
	baseRC, err := baseSrv.GetOrLoadRoundContext("cc", 5)
	require.NoError(t, err)
	require.Len(t, baseRC.SortedPubKeys, 3)

	// Invalidation scenario: index 2 is invalidated mid-dealing. network.Total is fixed
	// at BeginDealing to the verified count (3) and is never decremented, so the ALL-status
	// set keeps length 3 with the invalidated member in its slot. The VERIFIED-only set
	// would shrink to 2 and fail the len==Total check (asserted separately below).
	allStatuses := []*pb.DKGRegistration{
		{Index: 1, Round: 5, ValidatorAddr: "0xaaa", DkgPubKey: pubKeyBytes[0], Status: pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED},
		{Index: 2, Round: 5, ValidatorAddr: "0xbbb", DkgPubKey: pubKeyBytes[1], Status: pb.DKGRegStatus_DKG_REG_STATUS_INVALIDATED},
		{Index: 3, Round: 5, ValidatorAddr: "0xccc", DkgPubKey: pubKeyBytes[2], Status: pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED},
	}

	invStub := &stubQueryClient{
		networks:         []*pb.DKGNetwork{{Total: 3, Threshold: 2, Round: 5}},
		allRegistrations: allStatuses,
	}
	invSrv := &DKGServer{
		QueryClient:   invStub,
		Suite:         suite,
		RoundCtxCache: store.NewRoundContextCache(),
	}
	invRC, err := invSrv.GetOrLoadRoundContext("cc", 5)
	require.NoError(t, err)

	// Slot preserved: same length and same per-position keys as the all-verified case.
	require.Len(t, invRC.SortedPubKeys, 3, "invalidated member's slot must be preserved")
	for i := range baseRC.SortedPubKeys {
		require.True(t, baseRC.SortedPubKeys[i].Equal(invRC.SortedPubKeys[i]),
			"kyber position %d must match the all-verified list", i)
	}
	// Registrations now carries all statuses; the invalidated member is retained.
	require.Len(t, invRC.Registrations, 3)

	// A VERIFIED-only view (2 of 3) would fail validateRegistrations against the
	// unchanged network.Total=3 — the exact count mismatch the fix avoids.
	shrunkStub := &stubQueryClient{
		networks:         []*pb.DKGNetwork{{Total: 3, Threshold: 2, Round: 5}},
		allRegistrations: []*pb.DKGRegistration{allStatuses[0], allStatuses[2]},
	}
	shrunkSrv := &DKGServer{
		QueryClient:   shrunkStub,
		Suite:         suite,
		RoundCtxCache: store.NewRoundContextCache(),
	}
	_, err = shrunkSrv.GetOrLoadRoundContext("cc", 5)
	require.Error(t, err, "shrinking to the VERIFIED-only set must fail the count check")
}
