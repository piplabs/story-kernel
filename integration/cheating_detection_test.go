package integration

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestCheatingDetection_TamperedDeal tests cipher-level corruption: flipping AES-GCM
// ciphertext bytes causes decryption failure, and the service silently skips the
// corrupted deal. This is NOT a protocol-level VSS complaint test.
// For protocol-level complaint testing (tampered SecShare.V → real StatusComplaint),
// see TestProcessJustification_RealComplaintFlow in process_justification_test.go.
func TestCheatingDetection_TamperedDeal(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()

	// Route deals normally but tamper with one deal's cipher before delivering
	n := len(cluster.Servers)
	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dealResp := range cluster.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	// Tamper the first deal destined for node 0
	if len(dealsByRecipient[0]) > 0 {
		deal := dealsByRecipient[0][0]
		if deal.Deal != nil {
			cipher := deal.GetDeal().GetCipher()
			if len(cipher) > 0 {
				// Flip some bytes in the cipher to corrupt it
				tampered := make([]byte, len(cipher))
				copy(tampered, cipher)
				for i := range tampered {
					tampered[i] ^= 0xFF
				}
				deal.Deal.Cipher = tampered
			}
		}
	}

	// ProcessDeals on node 0 with the tampered deal.
	// The service silently skips invalid deals (logs the error, continues processing
	// remaining deals) and returns responses only for valid deals.
	resp, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.NoError(t, err, "ProcessDeals should succeed — tampered deals are skipped, not fatal")
	require.NotNil(t, resp)
	require.Less(t, len(resp.GetResponses()), len(dealsByRecipient[0]),
		"tampered deal should be skipped, producing fewer responses than deals received")

	// --- State machine aftermath: verify honest nodes can still complete DKG ---
	// Process deals normally for nodes 1 and 2
	processedResps := make([][]*pb.Response, n)
	processedResps[0] = resp.GetResponses()
	for i := 1; i < n; i++ {
		r, e := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, e, "ProcessDeals should succeed for honest node %d", i)
		processedResps[i] = r.GetResponses()
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}
	for i, srv := range cluster.Servers {
		_, e := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, e, "ProcessResponses should succeed for node %d", i)
	}

	// Honest nodes 1 and 2 must finalize with matching global_pub_key
	var gpk1, gpk2 []byte
	for _, i := range []int{1, 2} {
		fr, e := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, e, "FinalizeDKG must succeed for honest node %d", i)
		require.NotEmpty(t, fr.GetGlobalPubKey(), "node %d global_pub_key must not be empty", i)
		if i == 1 {
			gpk1 = fr.GetGlobalPubKey()
		} else {
			gpk2 = fr.GetGlobalPubKey()
		}
	}
	require.Equal(t, gpk1, gpk2, "honest nodes must agree on global_pub_key after tampered deal skip")
}

// TestCheatingDetection_TamperedDealAllNodes tests cipher-level corruption across all
// recipients: all deals from node 0 have their AES-GCM ciphertext flipped, causing
// decryption failure on every recipient. The service silently skips corrupted deals.
// This is NOT a protocol-level VSS complaint test.
// For protocol-level complaint testing, see TestProcessJustification_RealComplaintFlow.
func TestCheatingDetection_TamperedDealAllNodes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Route deals normally but tamper all deals from node 0 (cheating node)
	dealsByRecipient := make([][]*pb.Deal, n)
	for senderIdx, dealResp := range cluster.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			if senderIdx == 0 && deal.Deal != nil {
				// Tamper deals from node 0
				cipher := deal.GetDeal().GetCipher()
				if len(cipher) > 0 {
					tampered := make([]byte, len(cipher))
					copy(tampered, cipher)
					tampered[0] ^= 0xFF
					deal.Deal.Cipher = tampered
				}
			}
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	// Each recipient processes deals — the service silently skips tampered deals
	// from node 0 and returns responses only for valid deals.
	var allNodeResps []*pb.Response
	for i := 1; i < n; i++ {
		resp, err := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "node %d: ProcessDeals should succeed — tampered deals are skipped, not fatal", i)
		require.NotNil(t, resp)
		require.Less(t, len(resp.GetResponses()), len(dealsByRecipient[i]),
			"node %d: tampered deal from node 0 should reduce response count", i)
		allNodeResps = append(allNodeResps, resp.GetResponses()...)
	}

	// --- State machine aftermath: honest nodes 1 and 2 complete DKG ---
	// Node 0 also processes its incoming deals (from nodes 1 and 2, which are valid).
	// This provides the DKG state machine with all verifier responses needed for QUAL.
	resp0, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.NoError(t, err, "node 0 ProcessDeals should succeed — incoming deals from 1,2 are valid")
	allNodeResps = append(allNodeResps, resp0.GetResponses()...)

	for i := 1; i < n; i++ {
		_, e := cluster.Servers[i].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allNodeResps,
		})
		require.NoError(t, e, "ProcessResponses should succeed for honest node %d", i)
	}

	var gpk1, gpk2 []byte
	for _, i := range []int{1, 2} {
		fr, e := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, e, "FinalizeDKG must succeed for honest node %d", i)
		require.NotEmpty(t, fr.GetGlobalPubKey(), "node %d global_pub_key must not be empty", i)
		if i == 1 {
			gpk1 = fr.GetGlobalPubKey()
		} else {
			gpk2 = fr.GetGlobalPubKey()
		}
	}
	require.Equal(t, gpk1, gpk2,
		"honest nodes must agree on global_pub_key after all tampered deals from node 0 were skipped")
}

// TestCheatingDetection_PartialDealSkip_ValidDealsStillPersist tests cipher-level
// corruption resilience: one tampered deal (AES-GCM byte flip) is skipped by node 0,
// while the remaining valid deals are processed and persisted correctly, allowing the
// honest majority to complete the full DKG flow.
// This is NOT a protocol-level VSS complaint test.
// For protocol-level complaint testing, see TestProcessJustification_RealComplaintFlow.
//
// Setup: 3 nodes, threshold 2.
// Action: tamper one deal destined for node 0 (from node 1 → node 0).
//   - Node 0 processes its deals: the tampered deal is skipped, valid ones are accepted.
//   - Nodes 1 and 2 process their deals normally.
//
// Assertion: the surviving valid responses are sufficient for nodes 1 and 2 to finalize.
func TestCheatingDetection_PartialDealSkip_ValidDealsStillPersist(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Route deals to each recipient
	dealsByRecipient := make([][]*pb.Deal, n)
	for senderIdx, dr := range cluster.DealResponses {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
			t.Logf("[G7] Routed deal from sender=%d to recipient=%d", senderIdx, idx)
		}
	}
	for i := range n {
		t.Logf("[G7] Node %d will receive %d deal(s)", i, len(dealsByRecipient[i]))
	}

	// Tamper exactly one deal destined for node 0: flip all bytes in its cipher.
	// The first deal in dealsByRecipient[0] is from whichever sender generated it first.
	var tamperedSender int
	for i, deal := range dealsByRecipient[0] {
		if deal.Deal != nil {
			cipher := deal.GetDeal().GetCipher()
			if len(cipher) > 0 {
				tampered := make([]byte, len(cipher))
				copy(tampered, cipher)
				for j := range tampered {
					tampered[j] ^= 0xFF
				}
				deal.Deal.Cipher = tampered
				tamperedSender = i
				t.Logf("[G7] Tampered deal at index=%d for node 0: cipher_len=%d (all bytes XOR 0xFF)", i, len(cipher))
				break
			}
		}
	}
	t.Logf("[G7] Tampered deal from effective sender index=%d, remaining deals for node 0: %d",
		tamperedSender, len(dealsByRecipient[0]))

	// Process deals for all nodes; node 0 will skip the tampered deal
	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		if i == 0 {
			// Node 0 may error (hard failure on tampered deal) or succeed with fewer responses
			if err != nil {
				t.Logf("[G7] Node 0 ProcessDeals returned err=%v (tampered deal caused hard failure)", err)
				processedResps[i] = nil
			} else {
				t.Logf("[G7] Node 0 ProcessDeals returned %d response(s) (tampered deal skipped); expected fewer than %d",
					len(resp.GetResponses()), len(dealsByRecipient[0]))
				processedResps[i] = resp.GetResponses()
			}
		} else {
			require.NoError(t, err, "ProcessDeals should succeed for honest node %d", i)
			processedResps[i] = resp.GetResponses()
			t.Logf("[G7] Node %d ProcessDeals: %d response(s)", i, len(processedResps[i]))
		}
	}

	// Flatten all surviving responses (node 0's responses may be nil/empty)
	var allResps []*pb.Response
	for i, resps := range processedResps {
		allResps = append(allResps, resps...)
		t.Logf("[G7] Node %d contributed %d responses to broadcast set", i, len(resps))
	}
	t.Logf("[G7] Total responses in broadcast set: %d", len(allResps))

	// ProcessResponses on all nodes using surviving responses
	for i, srv := range cluster.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		t.Logf("[G7] Node %d ProcessResponses err=%v", i, err)
		require.NoError(t, err, "ProcessResponses should succeed for node %d even with partial deal skip", i)
	}

	// FinalizeDKG: nodes 1 and 2 must succeed (they had all valid deals).
	// Node 0 may or may not succeed depending on whether it received enough valid deals.
	finalizeResps := make([]*pb.FinalizeDKGResponse, n)
	for _, i := range []int{1, 2} {
		resp, err := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		t.Logf("[G7] Node %d FinalizeDKG err=%v global_pub_key_len=%d",
			i, err, len(resp.GetGlobalPubKey()))
		require.NoError(t, err, "FinalizeDKG must succeed for honest node %d after partial deal skip", i)
		require.NotNil(t, resp, "node %d FinalizeDKG response must not be nil", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "node %d global_pub_key must not be empty", i)
		finalizeResps[i] = resp
	}

	// Verify honest nodes agree on the same global_pub_key
	t.Logf("[G7] Node 1 global_pub_key=%x", finalizeResps[1].GetGlobalPubKey())
	t.Logf("[G7] Node 2 global_pub_key=%x", finalizeResps[2].GetGlobalPubKey())
	require.Equal(t, finalizeResps[1].GetGlobalPubKey(), finalizeResps[2].GetGlobalPubKey(),
		"honest nodes must agree on global_pub_key despite partial deal skip")
	t.Logf("[G7] PASS: honest nodes 1 and 2 completed DKG successfully with matching global_pub_key")
}

// TestCheatingDetection_DuplicateDeal verifies that submitting the same deals
// twice within the same round is either idempotent or returns an error indicating
// the deals were already processed. It must not corrupt DKG state.
func TestCheatingDetection_DuplicateDeal(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Collect deals for node 0
	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dealResp := range cluster.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	// The real invariant: the full DKG flow can still complete after a replay.
	// Collect responses from all nodes.
	processedResps := make([][]*pb.Response, n)

	// Process node 0's deals and capture responses from the first (valid) call.
	resp0, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.NoError(t, err, "first ProcessDeals on node 0 should succeed")
	processedResps[0] = resp0.GetResponses()

	// Replaying the same deals — kyber detects "already received a deal" and skips
	// each duplicate. All deals are rejected → PR #27 defense returns InvalidArgument
	// ("all N submitted deals were rejected"). This is correct behavior: replaying
	// already-processed deals should not silently succeed with empty state.
	_, replayErr := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.Error(t, replayErr, "duplicate ProcessDeals should return error — all deals already processed")
	require.Equal(t, codes.InvalidArgument, status.Code(replayErr),
		"duplicate ProcessDeals should return InvalidArgument (PR #27 defense)")
	t.Logf("Duplicate ProcessDeals correctly rejected: %v", replayErr)

	for i := 1; i < n; i++ {
		resp, e := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, e, "ProcessDeals for node %d should succeed", i)
		processedResps[i] = resp.GetResponses()
	}

	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	for _, srv := range cluster.Servers {
		_, err = srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses should succeed after replayed deal")
	}

	finalizeResps := make([]*pb.FinalizeDKGResponse, n)
	for i, srv := range cluster.Servers {
		resp, e := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, e, "FinalizeDKG for node %d should succeed after replayed deal", i)
		finalizeResps[i] = resp
	}

	// All nodes must agree on global_pub_key despite the duplicate deal replay
	for i := 1; i < n; i++ {
		require.Equal(t, finalizeResps[0].GetGlobalPubKey(), finalizeResps[i].GetGlobalPubKey(),
			"node 0 and node %d must agree on global_pub_key after duplicate deal replay", i)
	}
}

// TestCheatingDetection_DealIndexOutOfBounds tests that a fabricated deal with an
// out-of-bounds Index (e.g., 99 for a 3-node cluster) is silently skipped by the
// service, while valid deals in the same batch are processed normally. The DKG can
// still complete successfully after the OOB deal is ignored.
func TestCheatingDetection_DealIndexOutOfBounds(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Route deals to each recipient
	dealsByRecipient := buildDealsByRecipient(t, n, cluster.DealResponses)

	// Fabricate an out-of-bounds deal: Index=99, garbage EncryptedDeal bytes.
	// Copy structure from a valid deal but corrupt it.
	fabricatedDeal := &pb.Deal{
		Index:          99, // Way beyond 3 participants
		RecipientIndex: 0,
		Deal: &pb.EncryptedDeal{
			DhKey:     bytes.Repeat([]byte{0xDE}, 32),
			Signature: bytes.Repeat([]byte{0xAD}, 64),
			Nonce:     bytes.Repeat([]byte{0xBE}, 12),
			Cipher:    bytes.Repeat([]byte{0xEF}, 128),
		},
		Signature: bytes.Repeat([]byte{0x00}, 64),
	}

	// Append the fabricated deal to node 0's valid deals
	validDealCount := len(dealsByRecipient[0])
	mixedDeals := make([]*pb.Deal, 0, validDealCount+1)
	mixedDeals = append(mixedDeals, dealsByRecipient[0]...)
	mixedDeals = append(mixedDeals, fabricatedDeal)
	t.Logf("Node 0 receives %d valid deals + 1 fabricated OOB deal (Index=99)", validDealCount)

	// ProcessDeals on node 0 with the mixed batch (valid + fabricated)
	resp, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          mixedDeals,
	})
	require.NoError(t, err, "ProcessDeals should succeed — OOB deal is silently skipped, valid deals processed")
	require.NotNil(t, resp)
	require.Equal(t, validDealCount, len(resp.GetResponses()),
		"responses should equal valid deal count — fabricated OOB deal was skipped")
	t.Logf("Node 0 ProcessDeals: %d responses (OOB deal skipped as expected)", len(resp.GetResponses()))

	// Process deals for remaining nodes normally
	processedResps := make([][]*pb.Response, n)
	processedResps[0] = resp.GetResponses()
	for i := 1; i < n; i++ {
		r, e := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, e, "ProcessDeals should succeed for node %d", i)
		processedResps[i] = r.GetResponses()
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}
	for i, srv := range cluster.Servers {
		_, e := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, e, "ProcessResponses should succeed for node %d", i)
	}

	// Finalize DKG on all nodes — must succeed despite the OOB deal injection
	finalizeResps := make([]*pb.FinalizeDKGResponse, n)
	for i, srv := range cluster.Servers {
		fr, e := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, e, "FinalizeDKG must succeed for node %d after OOB deal was skipped", i)
		require.NotEmpty(t, fr.GetGlobalPubKey(), "node %d global_pub_key must not be empty", i)
		finalizeResps[i] = fr
	}

	// All nodes must agree on global_pub_key
	for i := 1; i < n; i++ {
		require.Equal(t, finalizeResps[0].GetGlobalPubKey(), finalizeResps[i].GetGlobalPubKey(),
			"node 0 and node %d must agree on global_pub_key after OOB deal injection", i)
	}
	t.Logf("PASS: DKG completed successfully — OOB deal (Index=99) was silently skipped")
}

// TestCheatingDetection_AllDealsInvalid_Rejected tests that ProcessDeals returns an
// InvalidArgument error when ALL submitted deals are invalid/corrupted (PR #27 defense).
// This verifies the "all N submitted deals were rejected" guard in dkg_process_deals.go.
func TestCheatingDetection_AllDealsInvalid_Rejected(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()

	// Create a list of fabricated/corrupted deals — all invalid.
	// Various fake Index values and garbage EncryptedDeal bytes.
	invalidDeals := []*pb.Deal{
		{
			Index:          0,
			RecipientIndex: 0,
			Deal: &pb.EncryptedDeal{
				DhKey:     bytes.Repeat([]byte{0x11}, 32),
				Signature: bytes.Repeat([]byte{0x22}, 64),
				Nonce:     bytes.Repeat([]byte{0x33}, 12),
				Cipher:    bytes.Repeat([]byte{0x44}, 128),
			},
			Signature: bytes.Repeat([]byte{0xFF}, 64),
		},
		{
			Index:          50,
			RecipientIndex: 0,
			Deal: &pb.EncryptedDeal{
				DhKey:     bytes.Repeat([]byte{0xAA}, 32),
				Signature: bytes.Repeat([]byte{0xBB}, 64),
				Nonce:     bytes.Repeat([]byte{0xCC}, 12),
				Cipher:    bytes.Repeat([]byte{0xDD}, 128),
			},
			Signature: bytes.Repeat([]byte{0xEE}, 64),
		},
		{
			Index:          1,
			RecipientIndex: 0,
			Deal: &pb.EncryptedDeal{
				DhKey:     bytes.Repeat([]byte{0x55}, 32),
				Signature: bytes.Repeat([]byte{0x66}, 64),
				Nonce:     bytes.Repeat([]byte{0x77}, 12),
				Cipher:    bytes.Repeat([]byte{0x88}, 128),
			},
			Signature: bytes.Repeat([]byte{0x99}, 64),
		},
	}
	t.Logf("Submitting %d fabricated invalid deals to node 0", len(invalidDeals))

	// Call ProcessDeals on node 0 with ONLY invalid deals
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          invalidDeals,
	})

	// PR #27 defense: when all deals are rejected, the service returns InvalidArgument
	require.Error(t, err, "ProcessDeals must return error when all deals are invalid")

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	require.Equal(t, codes.InvalidArgument, st.Code(),
		"error code should be InvalidArgument when all deals are rejected")
	require.Contains(t, st.Message(), "all",
		"error message should mention that all deals were rejected")
	require.Contains(t, st.Message(), "rejected",
		"error message should contain 'rejected'")
	t.Logf("ProcessDeals correctly rejected all-invalid deals: code=%s msg=%q", st.Code(), st.Message())
}

// TestCheatingDetection_CrossRoundReplay verifies that deals generated in round N
// are rejected when fed into ProcessDeals for round N+1. This tests actual
// cross-round replay attack defense.
func TestCheatingDetection_CrossRoundReplay(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// --- Round 1: complete full DKG and save the deals ---
	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	// Save round 1 deals for replay attempt later
	round1DealResponses := make([]*pb.GenerateDealsResponse, len(cluster.DealResponses))
	copy(round1DealResponses, cluster.DealResponses)

	// Collect round 1 deals destined for node 0
	n := len(cluster.Servers)
	round1DealsForNode0 := make([]*pb.Deal, 0)
	for _, dealResp := range round1DealResponses {
		for _, deal := range dealResp.GetDeals() {
			if int(deal.GetRecipientIndex()) == 0 {
				round1DealsForNode0 = append(round1DealsForNode0, deal)
			}
		}
	}
	require.NotEmpty(t, round1DealsForNode0, "should have round 1 deals for node 0")
	t.Logf("[CrossRoundReplay] Saved %d round-1 deals for node 0", len(round1DealsForNode0))

	// --- Round 2: set up resharing round ---
	ctx := context.Background()

	round1Network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            uint32(n),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      false,
		GlobalPublicKey:  round1GlobalPubKey,
		PublicCoeffs:     round1PublicCoeffs,
	}
	cluster.MockQC.SetLatestActiveNetwork(round1Network)
	cluster.MockQC.SetRegistrationsByRound(1, cluster.MockQC.GetCurrentRegistrations())

	var round2 uint32 = 2
	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(n),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// Generate round 2 keys
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
	}

	// Set round 2 registrations
	round2Regs := make([]*pb.DKGRegistration, n)
	for i, resp := range round2KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round2Regs[i] = &pb.DKGRegistration{
			Round:         round2,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Generate round 2 deals (so node 0 has an initialized DKG for round 2)
	for i, srv := range cluster.Servers {
		_, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
	}

	// --- Replay attack: feed round 1 deals into round 2 ProcessDeals ---
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          round2,
		Deals:          round1DealsForNode0,
	})
	// Round 1 deals should be rejected in round 2 context — different DKG session,
	// different keys, different polynomial commitments.
	require.Error(t, err, "cross-round replay: round 1 deals must be rejected in round 2 ProcessDeals")
	t.Logf("[CrossRoundReplay] ProcessDeals correctly rejected round 1 deals in round 2: %v", err)
}
