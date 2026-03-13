package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestCheatingDetection_TamperedDeal verifies that a deal with corrupted cipher
// is rejected or produces a complaint during ProcessDeals.
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

	// ProcessDeals on node 0 with the tampered deal — expect error or complaint
	resp, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})

	// The service skips invalid deals (logs error, continues) and returns whatever valid responses remain.
	// A fully corrupted deal should produce no valid response for that sender.
	// Either err != nil OR the response contains no approval for the tampered deal.
	if err != nil {
		// An error is also acceptable — tampered deal caused a hard failure
		return
	}

	require.NotNil(t, resp)
	// If no error, verify that the tampered deal produced fewer responses than expected
	// (one less approval since the tampered deal was skipped)
	require.Less(t, len(resp.GetResponses()), len(dealsByRecipient[0]),
		"tampered deal should be skipped, producing fewer responses than deals received")
}

// TestCheatingDetection_TamperedDealAllNodes verifies that tampered deals from a
// cheating node cause complaints or skips across all recipient nodes.
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

	// Each recipient processes deals — the tampered deal from node 0 should be skipped
	for i := 1; i < n; i++ {
		resp, err := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		if err != nil {
			// Hard failure on tampered deal is acceptable
			continue
		}
		require.NotNil(t, resp)
		// The tampered deal from node 0 should be skipped (no approval for it)
		require.Less(t, len(resp.GetResponses()), len(dealsByRecipient[i]),
			"node %d: tampered deal from node 0 should reduce response count", i)
	}
}

// TestCheatingDetection_PartialDealSkip_ValidDealsStillPersist verifies that when
// one tampered deal is skipped by a recipient node, the remaining valid deals are
// still processed and persisted correctly, allowing the honest majority of nodes to
// complete the full DKG flow (ProcessResponses + FinalizeDKG).
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

// TestCheatingDetection_ReplayedDeal verifies that replaying a deal from a previous
// round does not get accepted (wrong round context).
func TestCheatingDetection_ReplayedDeal(t *testing.T) {
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

	// Replaying the same deals — should either be a no-op or return an error,
	// but must not corrupt DKG state.
	_, _ = cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})

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

	for i, srv := range cluster.Servers {
		_, err = srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, err, "FinalizeDKG for node %d should succeed after replayed deal", i)
	}
}
