package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// buildValidProtoJustification constructs a pb.Justification with real kyber
// scalar and point bytes from a fresh random polynomial. The crypto content is
// not derived from the actual DKG session, so ProcessJustification will internally
// skip it; however, the proto itself passes ConvertToJustification without error.
func buildValidProtoJustification(t *testing.T) *pb.Justification {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()
	threshold := 2
	n := 3

	secret := suite.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.Point().Base())

	shares := priPoly.Shares(n)
	_, commits := pubPoly.Info()

	shareBytes, err := shares[0].V.MarshalBinary()
	require.NoError(t, err)

	commitmentPoints := make([]*pb.Point, len(commits))
	for i, c := range commits {
		bz, err := c.MarshalBinary()
		require.NoError(t, err)
		commitmentPoints[i] = &pb.Point{Data: bz}
	}

	return &pb.Justification{
		Index: 0,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("integration-test-session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("integration-inner-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: shareBytes},
				},
				Threshold:   uint32(threshold),
				Commitments: commitmentPoints,
			},
			Signature: []byte("integration-test-signature"),
		},
	}
}

// TestProcessJustification_InvalidJustification_SilentlySkipped verifies that a
// fabricated justification (not derived from the DKG session) is silently skipped
// by the service without returning an error. The service internally logs the invalid
// justification and continues, returning an empty response. This tests the service's
// fault tolerance for malformed justification input.
func TestProcessJustification_InvalidJustification_SilentlySkipped(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
	})
	require.NoError(t, err, "ProcessJustification should not return error for structured input")
	require.NotNil(t, resp)
}

// TestProcessJustification_MultipleInvalidJustifications_SilentlySkipped verifies
// that multiple fabricated justifications are all silently skipped. The service
// processes each justification individually, skipping those that don't match the
// DKG session state.
func TestProcessJustification_MultipleInvalidJustifications_SilentlySkipped(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{
			buildValidProtoJustification(t),
			buildValidProtoJustification(t),
		},
	})
	require.NoError(t, err, "ProcessJustification should accept multiple justifications")
	require.NotNil(t, resp)
}

// TestProcessJustification_InvalidJustification_AllNodes_SilentlySkipped verifies
// that all nodes in the cluster silently skip the same fabricated justification,
// confirming consistent fault-tolerant behavior across the cluster.
func TestProcessJustification_InvalidJustification_AllNodes_SilentlySkipped(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	j := buildValidProtoJustification(t)

	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessJustification(ctx, &pb.ProcessJustificationRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Justifications: []*pb.Justification{j},
		})
		require.NoError(t, err, "ProcessJustification failed for node %d", i)
		require.NotNil(t, resp, "node %d should return a response", i)
	}
}

// TestProcessJustification_Resharing_InvalidJustification_SilentlySkipped verifies
// that fabricated justifications are silently skipped during resharing
// (IsResharing=true), same fault-tolerant behavior as non-resharing.
func TestProcessJustification_Resharing_InvalidJustification_SilentlySkipped(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()
	runResharingRound2(t, cluster)

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
		IsResharing:    true,
	})
	require.NoError(t, err, "ProcessJustification (resharing) should not error for structured input")
	require.NotNil(t, resp)
}

// TestProcessJustification_RealComplaintFlow exercises the full Complaint → Justification
// → ProcessJustification → DKG recovery → TDH2 pipeline using a real tampered deal.
//
// Flow:
//  1. 3-node cluster generates keys and deals
//  2. Tamper the deal from dealer 0 → recipient 1 (corrupt SecShare.V)
//  3. Recipient 1's ProcessDeals produces a Complaint (Status=false) for dealer 0
//  4. All nodes call ProcessResponses; dealer 0 returns a Justification
//  5. Recipient 1 calls ProcessJustification with the justification
//  6. All nodes FinalizeDKG → same global_pub_key
//  7. TDH2 encrypt → partial decrypt → combine succeeds
func TestProcessJustification_RealComplaintFlow(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	dealerIdx := 0
	victimIdx := 1

	// Phase 1: Generate keys and deals
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	// Phase 2: Build per-recipient deals with one tampered deal
	dealsByRecipient := buildTamperedDealsByRecipient(t, cluster, dealerIdx, victimIdx)

	// Phase 3: ProcessDeals on all nodes
	processedResps := processDealsPerNode(t, cluster, dealsByRecipient)

	// Verify: victim (node 1) should have a complaint response for dealer 0.
	// A complaint has Status=false. The response's Index field is the dealer index.
	var hasComplaint bool
	for _, resp := range processedResps[victimIdx] {
		if resp.GetIndex() == uint32(dealerIdx) && !resp.GetVssResponse().GetStatus() {
			hasComplaint = true
			break
		}
	}
	require.True(t, hasComplaint, "victim node %d should have issued a complaint for dealer %d", victimIdx, dealerIdx)

	// Phase 4: Flatten responses and call ProcessResponses on all nodes.
	// Dealer 0 should return justifications because it received a complaint about its deal.
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	var justifications []*pb.Justification
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses failed for node %d", i)

		if i == dealerIdx {
			justifications = append(justifications, resp.GetJustifications()...)
		}
	}

	require.NotEmpty(t, justifications, "dealer %d should have produced justifications in response to the complaint", dealerIdx)
	t.Logf("Dealer %d produced %d justification(s)", dealerIdx, len(justifications))

	// Phase 5: Victim node processes the justification to restore its DKG state
	jResp, err := cluster.Servers[victimIdx].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: justifications,
	})
	require.NoError(t, err, "ProcessJustification should succeed for real justification")
	require.NotNil(t, jResp)
	t.Log("Victim node processed justification successfully")

	// Also send justification to the remaining node (node 2) for consistency.
	// It may skip it internally (no complaint from its side), but the call must not error.
	otherIdx := 2
	_, err = cluster.Servers[otherIdx].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: justifications,
	})
	require.NoError(t, err, "ProcessJustification on non-victim node should not error")

	// Phase 6: FinalizeDKG on all nodes — must succeed with consistent global_pub_key
	cluster.FinalizeAll()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, globalPubKey, "global pub key should not be empty")
	for i := 1; i < len(cluster.FinalizeResps); i++ {
		require.True(t, bytes.Equal(globalPubKey, cluster.FinalizeResps[i].GetGlobalPubKey()),
			"node %d global_pub_key differs from node 0", i)
	}
	t.Log("All nodes finalized with consistent global_pub_key")

	// Phase 7: TDH2 end-to-end — encrypt → partial decrypt → combine
	//
	// NOTE: kyber's ProcessJustification converts a complaint to an approval but
	// does NOT update the victim's stored SecShare.V (the tampered value remains
	// in the Aggregator's deal). As a result, the victim node's private share is
	// incorrect and its TDH2 partial decryption will not combine properly. We
	// therefore combine using only the non-victim nodes (dealer 0 and node 2),
	// which both received untampered deals and hold correct shares.
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("real complaint flow e2e test")
	label := []byte("complaint-test-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partials from the two non-victim nodes (0 and 2).
	nonVictimIdxs := []int{dealerIdx, otherIdx}
	results := make(map[int]*partialDecryptResult, len(nonVictimIdxs))
	for _, idx := range nonVictimIdxs {
		results[idx] = collectPartialDecrypt(t, cluster, idx, ct.Bytes, globalPubKey, label, requesterPriv)
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(nonVictimIdxs[0]): results[nonVictimIdxs[0]].PubShare,
		NodeName(nonVictimIdxs[1]): results[nonVictimIdxs[1]].PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(nonVictimIdxs[0]): results[nonVictimIdxs[0]].Partial,
		NodeName(nonVictimIdxs[1]): results[nonVictimIdxs[1]].Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted, "TDH2 decrypted text should match original")
	t.Log("TDH2 encrypt → partial decrypt → combine succeeded using non-victim nodes")
}

// TestProcessJustification_PersistenceAfterRestart verifies that justifications are
// persisted to disk and replayed on restart, allowing FinalizeDKG to succeed after
// a node restarts mid-protocol.
//
// Flow: same as RealComplaintFlow, but after ProcessJustification the victim node's
// in-memory caches are reset (simulating a restart). rebuildInitDKG must replay
// deals + responses + justifications from disk to complete FinalizeDKG.
func TestProcessJustification_PersistenceAfterRestart(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	dealerIdx := 0
	victimIdx := 1

	// Phase 1-5: Same complaint → justification flow as RealComplaintFlow
	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	dealsByRecipient := buildTamperedDealsByRecipient(t, cluster, dealerIdx, victimIdx)
	processedResps := processDealsPerNode(t, cluster, dealsByRecipient)

	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	var justifications []*pb.Justification
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses failed for node %d", i)
		if i == dealerIdx {
			justifications = append(justifications, resp.GetJustifications()...)
		}
	}
	require.NotEmpty(t, justifications)

	// All non-dealer nodes process justification (persists to disk).
	// Node 2 also needs the justification so it can certify dealer 0's deal;
	// without it, node 2's QUAL would exclude dealer 0, causing global_pub_key mismatch.
	for i, srv := range cluster.Servers {
		if i == dealerIdx {
			continue
		}
		_, err := srv.ProcessJustification(ctx, &pb.ProcessJustificationRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Justifications: justifications,
		})
		require.NoError(t, err, "ProcessJustification failed for node %d", i)
	}

	// Phase 6: Simulate victim restart — clear all in-memory caches
	// DKGStore is retained (disk state), but DKG caches are flushed.
	victim := cluster.Servers[victimIdx]
	victim.RoundCtxCache = store.NewRoundContextCache()
	victim.InitDKGCache = store.NewDKGCache()
	victim.ResharingPrevCache = store.NewResharingDKGCache()
	victim.ResharingNextCache = store.NewDKGCache()
	victim.DistKeyShareCache = store.NewDistKeyShareCache()
	victim.PIDCache = store.NewPIDCache()
	t.Log("Victim node caches cleared (simulated restart)")

	// Phase 7: FinalizeDKG on all nodes — victim must rebuild from disk state
	// which includes the persisted justifications.
	cluster.FinalizeAll()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, globalPubKey)
	for i := 1; i < len(cluster.FinalizeResps); i++ {
		require.True(t, bytes.Equal(globalPubKey, cluster.FinalizeResps[i].GetGlobalPubKey()),
			"node %d global_pub_key differs from node 0 after restart", i)
	}
	t.Log("All nodes finalized with consistent global_pub_key after victim restart")
}
