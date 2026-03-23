package integration

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// ---------- A2: QueryClient returns inconsistent data ----------

// TestQueryInconsistency_RegistrationCountLessThanTotal verifies behavior when
// network.Total=3 but only 2 registrations are returned.
// This can happen if a validator fails to register before the dealing phase starts.
func TestQueryInconsistency_RegistrationCountLessThanTotal(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys for only 2 of 3 nodes
	ctx := context.Background()
	keyResps := make([]*pb.GenerateAndSealKeyResponse, 2)
	for i := 0; i < 2; i++ {
		resp, err := cluster.Servers[i].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err)
		keyResps[i] = resp
	}

	// Set only 2 registrations while network.Total=3
	regs := make([]*pb.DKGRegistration, 2)
	for i, resp := range keyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:         cluster.Round,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(regs)

	// Reset cache to force re-fetch
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Issue #23: service should validate len(registrations) vs network.Total but doesn't.
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	assert.Error(t, err, "GenerateDeals should reject mismatched registration count vs network.Total (issue #23)")
}

// TestQueryInconsistency_DuplicateRegistrationIndex verifies behavior when
// two registrations have the same Index value.
func TestQueryInconsistency_DuplicateRegistrationIndex(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys normally
	cluster.GenerateAllKeys()

	// Tamper: set duplicate index on registration[1]
	regs := cluster.MockQC.GetCurrentRegistrations()
	regs[1].Index = regs[0].Index // duplicate index

	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Issue #23: service should validate duplicate registration indices but doesn't.
	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	assert.Error(t, err, "GenerateDeals should reject duplicate registration indices (issue #23)")
}

// TestQueryInconsistency_ThresholdExceedsTotal verifies behavior when
// threshold > total (e.g., threshold=3, total=2).
func TestQueryInconsistency_ThresholdExceedsTotal(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	// Create network with invalid threshold > total
	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            2,
		Threshold:        3, // invalid: threshold > total
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}

	cluster := &DKGTestCluster{
		t:              t,
		MockQC:         NewMockQueryClient(network),
		CodeCommitment: codeCommitment,
		Round:          1,
		Threshold:      3,
	}

	// Build 2 servers
	servers, addresses, tempDirs := buildFreshServers(t, cluster.MockQC, 2, 0)
	cluster.Servers = servers
	cluster.Addresses = addresses
	cluster.TempDirs = tempDirs
	defer cluster.Cleanup()

	// Generate keys for both nodes
	ctx := context.Background()
	keyResps := make([]*pb.GenerateAndSealKeyResponse, 2)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err)
		keyResps[i] = resp
	}

	// Set registrations
	regs := make([]*pb.DKGRegistration, 2)
	for i, resp := range keyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:         cluster.Round,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// GenerateDeals with threshold > total should fail
	_, err = cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "GenerateDeals should fail when threshold > total")
}

// TestQueryInconsistency_ZeroThreshold verifies behavior when threshold=0.
// Must not cause division by zero or kyber panic.
func TestQueryInconsistency_ZeroThreshold(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            3,
		Threshold:        0, // invalid
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}

	cluster := &DKGTestCluster{
		t:              t,
		MockQC:         NewMockQueryClient(network),
		CodeCommitment: codeCommitment,
		Round:          1,
		Threshold:      0,
	}

	servers, addresses, tempDirs := buildFreshServers(t, cluster.MockQC, 3, 0)
	cluster.Servers = servers
	cluster.Addresses = addresses
	cluster.TempDirs = tempDirs
	defer cluster.Cleanup()

	// Generate keys
	ctx := context.Background()
	keyResps := make([]*pb.GenerateAndSealKeyResponse, 3)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err)
		keyResps[i] = resp
	}

	regs := make([]*pb.DKGRegistration, 3)
	for i, resp := range keyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:         cluster.Round,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// GenerateDeals with threshold=0 should fail. The service validates threshold > 0
	// in buildInitDKG before calling kyber. Tests call the service directly (not via gRPC),
	// so this is a service-level error, not a gRPC recovery.
	_, err = cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "GenerateDeals should fail when threshold=0")
}

// TestQueryInconsistency_RegistrationCountMoreThanTotal verifies behavior when
// more registrations are returned than network.Total declares.
func TestQueryInconsistency_RegistrationCountMoreThanTotal(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	// Network says total=2 but we'll provide 3 registrations
	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            2, // only 2 expected
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}

	cluster := &DKGTestCluster{
		t:              t,
		MockQC:         NewMockQueryClient(network),
		CodeCommitment: codeCommitment,
		Round:          1,
		Threshold:      2,
	}

	servers, addresses, tempDirs := buildFreshServers(t, cluster.MockQC, 3, 0)
	cluster.Servers = servers
	cluster.Addresses = addresses
	cluster.TempDirs = tempDirs
	defer cluster.Cleanup()

	// Generate keys for all 3 nodes
	ctx := context.Background()
	keyResps := make([]*pb.GenerateAndSealKeyResponse, 3)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err)
		keyResps[i] = resp
	}

	// Set 3 registrations when network.Total=2
	regs := make([]*pb.DKGRegistration, 3)
	for i, resp := range keyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:         cluster.Round,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Issue #23: service should validate len(registrations) vs network.Total but doesn't.
	_, err = cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	assert.Error(t, err, "GenerateDeals should reject more registrations than network.Total (issue #23)")
}

// TestQueryInconsistency_RoundMismatch verifies behavior when registration round
// doesn't match the requested round.
func TestQueryInconsistency_RoundMismatch(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys normally
	cluster.GenerateAllKeys()

	// Tamper: set all registrations to round 99 (mismatched)
	regs := cluster.MockQC.GetCurrentRegistrations()
	for _, reg := range regs {
		reg.Round = 99
	}
	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Issue #23: service should validate registration.Round vs request round but doesn't.
	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round, // round=1 but registrations say round=99
	})
	assert.Error(t, err, "GenerateDeals should reject registration round mismatch (issue #23)")
}

// TestQueryInconsistency_DuplicateIndex_PropagatesThroughDKG verifies what happens when
// duplicate registration indices are silently accepted by GenerateDeals and the full DKG
// flow is executed. This test documents whether duplicate indices cause a downstream
// failure or silently produce an incorrect result.
func TestQueryInconsistency_DuplicateIndex_PropagatesThroughDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys normally
	cluster.GenerateAllKeys()

	// Tamper: set duplicate index on registration[1] (same as registration[0])
	regs := cluster.MockQC.GetCurrentRegistrations()
	regs[1].Index = regs[0].Index // duplicate index
	cluster.MockQC.SetRegistrations(regs)
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	ctx := context.Background()

	// GenerateDeals: PR #27 added validateRegistrations() in fetchRoundContext(),
	// which now catches duplicate indices at the earliest entry point.
	// The first node to call GenerateDeals triggers fetchRoundContext() → validateRegistrations()
	// → "duplicate registration index" error.
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "GenerateDeals must fail — duplicate index now caught by validateRegistrations (PR #27)")
	t.Logf("PASS: duplicate index caught at GenerateDeals → fetchRoundContext → validateRegistrations: %v", err)
}
