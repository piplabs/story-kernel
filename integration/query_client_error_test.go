package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// ---------- A1: QueryClient returns errors ----------

// TestQueryError_GetDKGNetwork_GenerateAndSealKey verifies that when GetDKGNetwork
// returns an error, GenerateAndSealKey fails gracefully (not panic).
// GenerateAndSealKey calls GetOrLoadRoundContext which calls GetDKGNetwork.
func TestQueryError_GetDKGNetwork_GenerateAndSealKey(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Inject error before any key generation so RoundCtxCache is empty
	cluster.MockQC.SetGetDKGNetworkError(fmt.Errorf("simulated chain unavailable"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "GenerateAndSealKey should fail when GetDKGNetwork returns error")

	// Clear error and verify recovery
	cluster.MockQC.SetGetDKGNetworkError(nil)
	resp, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.NoError(t, err, "GenerateAndSealKey should succeed after error is cleared")
	require.NotNil(t, resp)
}

// TestQueryError_GetRegistrations_GenerateAndSealKey verifies that when
// GetAllParticipantDKGRegistrations returns an error, GenerateAndSealKey still succeeds
// because GenerateAndSealKey only calls GetDKGNetwork (not registrations).
// No registrations exist yet at key generation time.
func TestQueryError_GetRegistrations_GenerateAndSealKey(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.MockQC.SetGetRegistrationsError(fmt.Errorf("simulated registrations query failed"))

	ctx := context.Background()
	resp, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.NoError(t, err, "GenerateAndSealKey should succeed even when registrations error is injected")
	require.NotNil(t, resp, "response should not be nil")
	require.NotEmpty(t, resp.GetDkgPubKey(), "DKG public key should be returned")
}

// TestQueryError_VerifyStartBlock_GenerateAndSealKey verifies that when VerifyStartBlock
// returns an error, GenerateAndSealKey rejects the request.
// This is a critical security check: VerifyStartBlock ensures the DKG round was
// legitimately initiated on-chain. Current MockQueryClient always returns nil, so this
// code path has NEVER been tested.
func TestQueryError_VerifyStartBlock_GenerateAndSealKey(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Inject VerifyStartBlock error (GetDKGNetwork and GetRegistrations still succeed)
	cluster.MockQC.SetVerifyStartBlockError(fmt.Errorf("start block not on canonical chain"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "GenerateAndSealKey should fail when VerifyStartBlock returns error")
}

// TestQueryError_GetDKGNetwork_GenerateDeals verifies that when GetDKGNetwork
// returns an error, GenerateDeals fails.
func TestQueryError_GetDKGNetwork_GenerateDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys normally (VerifyStartBlock returns nil by default)
	cluster.GenerateAllKeys()

	// After GenerateAllKeys, RoundCtxCache is reset. Inject error before GenerateDeals.
	cluster.MockQC.SetGetDKGNetworkError(fmt.Errorf("simulated chain unavailable"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "GenerateDeals should fail when GetDKGNetwork returns error")
}

// TestQueryError_GetDKGNetwork_ProcessDeals verifies that when GetDKGNetwork
// returns an error and RoundCtxCache is empty, ProcessDeals fails.
func TestQueryError_GetDKGNetwork_ProcessDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete keys + deals normally
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	// Build deals for node 0
	dealsByRecipient := buildDealsByRecipient(t, len(cluster.Servers), cluster.DealResponses)

	// Reset node 0's cache and inject error
	cluster.Servers[0].RoundCtxCache = store.NewRoundContextCache()
	cluster.MockQC.SetGetDKGNetworkError(fmt.Errorf("simulated chain unavailable"))

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.Error(t, err, "ProcessDeals should fail when GetDKGNetwork returns error and cache is empty")
}

// TestQueryError_GetLatestActiveNetwork_PartialDecrypt verifies that when
// GetLatestActiveDKGNetwork returns an error, PartialDecryptTDH2 fails.
// PartialDecryptTDH2 calls verifyRoundMatchesLatestNetwork which uses this method.
func TestQueryError_GetLatestActiveNetwork_PartialDecrypt(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete full DKG
	cluster.RunFullDKG()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("query error test")
	label := []byte("qerr-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Inject error
	cluster.MockQC.SetGetLatestActiveNetworkError(fmt.Errorf("simulated latest network query failed"))

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 should fail when GetLatestActiveDKGNetwork returns error")
}

// TestQueryError_HasDecryptRequest_PartialDecrypt verifies that when
// HasDecryptRequest returns an error, PartialDecryptTDH2 fails gracefully.
func TestQueryError_HasDecryptRequest_PartialDecrypt(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	label := []byte("qerr-decrypt-request-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("query error decrypt request test"), label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Inject error
	cluster.MockQC.SetHasDecryptRequestError(fmt.Errorf("simulated decrypt request query failed"))

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 should fail when HasDecryptRequest returns error")
	require.Contains(t, err.Error(), "verify decrypt request existence")
}

// TestQueryError_GetRegistrations_FinalizeDKG verifies that when
// GetAllParticipantDKGRegistrations returns an error during FinalizeDKG, it fails.
// FinalizeDKG calls GetAllParticipantDKGRegistrations directly (not via cache)
// to calculate participants root for the signature.
func TestQueryError_GetRegistrations_FinalizeDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete DKG up to ProcessResponses
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()
	cluster.ProcessAllResponses()

	// Inject error before FinalizeDKG
	cluster.MockQC.SetGetRegistrationsError(fmt.Errorf("simulated registrations query failed"))

	ctx := context.Background()
	_, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "FinalizeDKG should fail when GetAllParticipantDKGRegistrations returns error")
}

// TestQueryError_GetRegistrations_GenerateDeals verifies that when
// GetAllParticipantDKGRegistrations returns an error during GenerateDeals, it fails.
// GenerateDeals calls GetOrLoadRoundContext which calls GetDKGNetwork (succeeds)
// then GetAllParticipantDKGRegistrations (fails). RoundCtxCache is reset to force re-fetch.
func TestQueryError_GetRegistrations_GenerateDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Generate keys normally so that GenerateDeals has Ed25519 keys on disk
	cluster.GenerateAllKeys()

	// Reset RoundCtxCache on all servers so GenerateDeals must re-fetch from QueryClient
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Inject registrations error — GetDKGNetwork succeeds but GetAllParticipantDKGRegistrations fails
	cluster.MockQC.SetGetRegistrationsError(fmt.Errorf("simulated registrations error"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.Error(t, err, "GenerateDeals should fail when GetAllParticipantDKGRegistrations returns error")

	// Clear error and verify recovery
	cluster.MockQC.SetGetRegistrationsError(nil)
}

// TestQueryError_GetDKGNetwork_ProcessResponses verifies that when GetDKGNetwork
// returns an error and RoundCtxCache is empty, ProcessResponses fails.
// ProcessResponses calls GetOrLoadRoundContext which calls GetDKGNetwork.
func TestQueryError_GetDKGNetwork_ProcessResponses(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete DKG up to ProcessDeals
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()

	// Flatten all responses from ProcessDeals
	var allResps []*pb.Response
	for _, resps := range cluster.ProcessedResps {
		allResps = append(allResps, resps...)
	}

	// Reset node 0's RoundCtxCache so ProcessResponses must re-fetch via GetOrLoadRoundContext
	cluster.Servers[0].RoundCtxCache = store.NewRoundContextCache()

	// Inject GetDKGNetwork error
	cluster.MockQC.SetGetDKGNetworkError(fmt.Errorf("simulated chain unavailable"))

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Responses:      allResps,
	})
	require.Error(t, err, "ProcessResponses should fail when GetDKGNetwork returns error and cache is empty")

	// Clear error
	cluster.MockQC.SetGetDKGNetworkError(nil)
}

// TestQueryError_TransientError_RecoveryAfterClear verifies that after a transient
// QueryClient error is cleared, the full DKG flow can complete successfully.
// This simulates a brief chain outage followed by recovery.
func TestQueryError_TransientError_RecoveryAfterClear(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Step 1: Inject error — GenerateAndSealKey fails
	cluster.MockQC.SetGetDKGNetworkError(fmt.Errorf("transient chain outage"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "should fail during outage")

	// Step 2: Clear error — full DKG succeeds
	cluster.MockQC.SetGetDKGNetworkError(nil)

	cluster.RunFullDKG()

	// Verify all nodes agree on global public key
	for i := 1; i < len(cluster.FinalizeResps); i++ {
		require.Equal(t,
			cluster.FinalizeResps[0].GetGlobalPubKey(),
			cluster.FinalizeResps[i].GetGlobalPubKey(),
			"all nodes should agree on global public key after recovery",
		)
	}
}

// ---------- A1-R: Resharing QueryClient error injection ----------

// resharingSetup holds the state produced by setupResharingRound2BeforeDeals.
type resharingSetup struct {
	Cluster        *DKGTestCluster
	Round2Network  *pb.DKGNetwork
}

// setupResharingRound2BeforeDeals creates a 3-node cluster, completes round 1 DKG,
// and sets up MockQC for round 2 resharing — but stops before GenerateDeals.
// Callers can inject errors and then drive the resharing protocol manually.
func setupResharingRound2BeforeDeals(t *testing.T) *resharingSetup {
	t.Helper()
	ctx := context.Background()

	cluster := NewDKGTestCluster(t, 3, 2)
	t.Cleanup(cluster.Cleanup)

	// Complete round 1 DKG
	cluster.RunFullDKG()

	// Collect round 1 results
	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	// Set the "latest active network" to round 1
	round1Network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      false,
		GlobalPublicKey:  round1GlobalPubKey,
		PublicCoeffs:     round1PublicCoeffs,
	}
	cluster.MockQC.SetLatestActiveNetwork(round1Network)
	cluster.MockQC.SetRegistrationsByRound(1, cluster.MockQC.GetCurrentRegistrations())

	// Set up round 2 resharing network
	round2Network := &pb.DKGNetwork{
		Round:            2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// Generate round 2 keys on all nodes
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
	}

	// Build round 2 registrations
	round2Regs := make([]*pb.DKGRegistration, len(cluster.Servers))
	for i, resp := range round2KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round2Regs[i] = &pb.DKGRegistration{
			Round:         2,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(2, round2Regs)

	// Reset RoundCtxCache on all servers to pick up new registrations
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	return &resharingSetup{
		Cluster:       cluster,
		Round2Network: round2Network,
	}
}

// TestQueryError_Resharing_GetLatestActiveNetwork_GenerateDeals verifies that when
// GetLatestActiveDKGNetwork returns an error during resharing GenerateDeals, it fails
// gracefully and recovers after the error is cleared.
func TestQueryError_Resharing_GetLatestActiveNetwork_GenerateDeals(t *testing.T) {
	setup := setupResharingRound2BeforeDeals(t)
	cluster := setup.Cluster

	// Inject error before GenerateDeals
	cluster.MockQC.SetGetLatestActiveNetworkError(fmt.Errorf("simulated: latest active network unavailable"))

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
	})
	require.Error(t, err, "GenerateDeals should fail when GetLatestActiveDKGNetwork returns error")

	// Recovery: clear error, retry
	cluster.MockQC.SetGetLatestActiveNetworkError(nil)
	_, err = cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
	})
	require.NoError(t, err, "GenerateDeals should succeed after error is cleared")
}

// TestQueryError_Resharing_GetLatestActiveNetwork_ProcessResponses verifies that when
// GetLatestActiveDKGNetwork returns an error during resharing ProcessResponses, it fails.
func TestQueryError_Resharing_GetLatestActiveNetwork_ProcessResponses(t *testing.T) {
	setup := setupResharingRound2BeforeDeals(t)
	cluster := setup.Cluster
	ctx := context.Background()

	// Run GenerateDeals on all nodes
	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals to recipients
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)

	// ProcessDeals on all nodes, collect responses
	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals round 2 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
	}

	// Flatten all responses
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	// Inject error before ProcessResponses
	cluster.MockQC.SetGetLatestActiveNetworkError(fmt.Errorf("simulated: latest active network unavailable"))

	_, err := cluster.Servers[0].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
		Responses:      allResps,
	})
	require.Error(t, err, "ProcessResponses should fail when GetLatestActiveDKGNetwork returns error")
}

// TestQueryError_Resharing_GetLatestActiveNetwork_ProcessJustification verifies that when
// GetLatestActiveDKGNetwork returns an error during resharing ProcessJustification, it fails.
func TestQueryError_Resharing_GetLatestActiveNetwork_ProcessJustification(t *testing.T) {
	setup := setupResharingRound2BeforeDeals(t)
	cluster := setup.Cluster
	ctx := context.Background()

	// Run GenerateDeals on all nodes
	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals and ProcessDeals on all nodes
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)
	for i, srv := range cluster.Servers {
		_, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals round 2 failed for node %d", i)
	}

	// Inject error before ProcessJustification
	cluster.MockQC.SetGetLatestActiveNetworkError(fmt.Errorf("simulated: latest active network unavailable"))

	// Build a dummy justification — just needs to pass request validation.
	// The error occurs before justification content is processed.
	dummyJust := []*pb.Justification{{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("dummy-session"),
		},
	}}

	_, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
		Justifications: dummyJust,
	})
	require.Error(t, err, "ProcessJustification should fail when GetLatestActiveDKGNetwork returns error")
}

// TestQueryError_Resharing_GetLatestActiveNetwork_ProcessDeals verifies that when
// GetLatestActiveDKGNetwork returns an error during resharing ProcessDeals, it fails.
// This exercises GetResharingNextDKG's internal call to GetLatestActiveDKGNetwork.
func TestQueryError_Resharing_GetLatestActiveNetwork_ProcessDeals(t *testing.T) {
	setup := setupResharingRound2BeforeDeals(t)
	cluster := setup.Cluster
	ctx := context.Background()

	// Run GenerateDeals on all nodes
	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals to recipients
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)

	// Clear all caches and round-2 DKG state on disk so GetResharingNextDKG
	// enters the build path (not rebuild from disk), which calls GetLatestActiveDKGNetwork.
	cluster.Servers[0].ResharingNextCache = store.NewDKGCache()
	cluster.Servers[0].ResharingPrevCache = store.NewResharingDKGCache()
	cluster.Servers[0].InitDKGCache = store.NewDKGCache()
	cluster.Servers[0].RoundCtxCache = store.NewRoundContextCache()
	os.RemoveAll(filepath.Join(cluster.Servers[0].Cfg.GetDKGStateDir(), "2"))

	// Inject error
	cluster.MockQC.SetGetLatestActiveNetworkError(fmt.Errorf("simulated: latest active network unavailable"))

	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
		Deals:          dealsByRecipient[0],
	})
	require.Error(t, err, "ProcessDeals should fail when GetLatestActiveDKGNetwork returns error during resharing")
}

// TestQueryError_Resharing_GetRegistrations_FetchLatestPubKeysAndCoeffs verifies that when
// GetAllParticipantDKGRegistrations returns an error during resharing ProcessDeals, it fails.
// ProcessDeals in resharing mode calls fetchLatestPubKeysAndCoeffs which queries registrations.
func TestQueryError_Resharing_GetRegistrations_FetchLatestPubKeysAndCoeffs(t *testing.T) {
	setup := setupResharingRound2BeforeDeals(t)
	cluster := setup.Cluster
	ctx := context.Background()

	// Run GenerateDeals on all nodes
	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals to recipients
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)

	// Clear all caches and round-2 DKG state on disk (same as ProcessDeals test above)
	cluster.Servers[0].ResharingNextCache = store.NewDKGCache()
	cluster.Servers[0].ResharingPrevCache = store.NewResharingDKGCache()
	cluster.Servers[0].InitDKGCache = store.NewDKGCache()
	cluster.Servers[0].RoundCtxCache = store.NewRoundContextCache()
	os.RemoveAll(filepath.Join(cluster.Servers[0].Cfg.GetDKGStateDir(), "2"))

	// Inject registrations error
	cluster.MockQC.SetGetRegistrationsError(fmt.Errorf("simulated: registrations query failed"))

	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          2,
		IsResharing:    true,
		Deals:          dealsByRecipient[0],
	})
	require.Error(t, err, "ProcessDeals should fail when GetAllParticipantDKGRegistrations returns error during resharing")
}
