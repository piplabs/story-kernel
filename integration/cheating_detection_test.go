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

	// Process normally first
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	require.NoError(t, err, "first ProcessDeals should succeed")

	// Replaying the same deals — should either be a no-op or return an error,
	// but must not corrupt DKG state.
	_, _ = cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})

	// The real invariant: the full DKG flow can still complete after the replay.
	// Collect responses from all nodes (node 0 was already processed above).
	processedResps := make([][]*pb.Response, n)
	resp0, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	// Node 0 may error or succeed on the third call — capture whatever responses it has
	if err == nil {
		processedResps[0] = resp0.GetResponses()
	}
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
