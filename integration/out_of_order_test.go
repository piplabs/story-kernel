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

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestOutOfOrder_FinalizeDKG_SkipProcessResponses verifies that calling FinalizeDKG
// immediately after ProcessDeals (skipping ProcessResponses) fails because kyber
// cannot compute a DistKeyShare without sufficient response data.
func TestOutOfOrder_FinalizeDKG_SkipProcessResponses(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()
	// Skip ProcessAllResponses

	// Note: In Pedersen DKG with honest majority, kyber may treat zero complaints as
	// universal approval. This test assumes FinalizeDKG fails without explicit ProcessResponses.

	ctx := context.Background()
	for i, srv := range cluster.Servers {
		_, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.Error(t, err, "FinalizeDKG must fail for node %d when ProcessResponses was skipped", i)
	}
}

// TestOutOfOrder_FinalizeDKG_SkipProcessDealsAndResponses verifies that calling
// FinalizeDKG right after GenerateDeals (skipping both ProcessDeals and ProcessResponses)
// fails even more decisively — no deal or response data has been processed at all.
func TestOutOfOrder_FinalizeDKG_SkipProcessDealsAndResponses(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	// Skip ProcessAllDeals and ProcessAllResponses

	ctx := context.Background()
	for i, srv := range cluster.Servers {
		_, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.Error(t, err, "FinalizeDKG must fail for node %d when ProcessDeals and ProcessResponses were both skipped", i)
	}
}

// TestOutOfOrder_PartialDecrypt_BeforeFinalizeDKG verifies that PartialDecryptTDH2
// fails when DKG has not been finalized (no DistKeyShare on disk), even though the
// PIDCache was populated by GenerateDeals. This distinguishes from
// TestErrorValidation_PartialDecrypt_PIDNotCached, which clears the PIDCache entirely.
func TestOutOfOrder_PartialDecrypt_BeforeFinalizeDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals() // PIDCache is now populated
	// Skip ProcessDeals, ProcessResponses, FinalizeDKG

	ctx := context.Background()

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      []byte("any-dummy-ciphertext"),
		GlobalPubKey:    []byte("any-dummy-pubkey"),
		Label:           []byte("test"),
		RequesterPubKey: ecrypto.FromECDSAPub(&requesterPriv.PublicKey),
	})
	require.Error(t, err, "PartialDecryptTDH2 must fail when FinalizeDKG has not been called (no DistKeyShare on disk)")
}

// TestOutOfOrder_GenerateDeals_Repeated verifies that calling GenerateDeals twice for
// the same round succeeds without error, and the subsequent DKG flow (using the second
// response) still completes successfully.
//
// IMPORTANT: GenerateDeals is NOT idempotent. Each call generates fresh random polynomial
// coefficients, producing different deal ciphertexts. The second call's deals replace
// the first in the DKG state machine. This test confirms "fresh regeneration" behavior,
// not idempotency.
func TestOutOfOrder_GenerateDeals_Repeated(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()

	ctx := context.Background()
	n := len(cluster.Servers)

	// First round of GenerateDeals
	firstResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, err, "first GenerateDeals failed for node %d", i)
		firstResps[i] = resp
	}

	// Second round of GenerateDeals (same round)
	secondResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, err, "second GenerateDeals failed for node %d", i)
		secondResps[i] = resp
	}

	// Verify structural consistency: both calls return the same number of deals per node
	for i := range n {
		require.Len(t, secondResps[i].GetDeals(), len(firstResps[i].GetDeals()),
			"GenerateDeals must return the same number of deals on repeated calls: node %d", i)
	}

	// Verify deals have different content (fresh random coefficients each call)
	for i := range firstResps {
		if len(firstResps[i].GetDeals()) > 0 && len(secondResps[i].GetDeals()) > 0 {
			require.False(t, bytes.Equal(
				firstResps[i].GetDeals()[0].GetDeal().GetCipher(),
				secondResps[i].GetDeals()[0].GetDeal().GetCipher()),
				"node %d: repeated GenerateDeals should produce different ciphertexts", i)
		}
	}

	// Store second responses and verify the DKG can still complete using them
	cluster.DealResponses = secondResps
	cluster.ProcessAllDeals()
	cluster.ProcessAllResponses()
	cluster.FinalizeAll()

	require.NotEmpty(t, cluster.FinalizeResps[0].GetGlobalPubKey(),
		"GlobalPubKey must be non-empty after completing DKG with second GenerateDeals responses")
}

// TestOutOfOrder_ProcessDeals_AfterFinalizeDKG verifies that re-submitting deals to a
// node that has already finalized DKG (late/replayed deal messages) does not corrupt
// the sealed DistKeyShare. PartialDecryptTDH2 must still produce correct results.
func TestOutOfOrder_ProcessDeals_AfterFinalizeDKG(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	// Reconstruct the deals that were originally sent to node 0 (index 0)
	dealsByRecipient := make([][]*pb.Deal, len(cluster.Servers))
	for _, dealResp := range cluster.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}
	lateDeals := dealsByRecipient[0]
	require.NotEmpty(t, lateDeals, "expected deals for node 0 to be non-empty")

	// Late ProcessDeals after finalization: the service may succeed or fail.
	// The critical assertion is that it does NOT corrupt the sealed DistKeyShare.
	ctx := context.Background()
	lateResp, lateErr := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          lateDeals,
	})
	if lateErr != nil {
		t.Logf("Late ProcessDeals returned error (acceptable): %v", lateErr)
	} else {
		t.Logf("Late ProcessDeals returned success with %d responses (acceptable — no corruption)", len(lateResp.GetResponses()))
	}

	// Verify that PartialDecryptTDH2 still works correctly end-to-end.
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("late deal must not corrupt sealed share")
	label := []byte("out-of-order-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(1): result1.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(1): result1.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted,
		"PartialDecryptTDH2 must still produce correct results after late ProcessDeals")
}

// TestOutOfOrder_ProcessResponses_BeforeProcessDeals verifies the behavior when
// ProcessResponses is called on a node that skipped ProcessDeals.
//
// Service behavior: GetInitDKG creates a fresh DistKeyGenerator (node has a sealed
// key from GenerateAndSealKey). ProcessResponse for each response fails individually
// (no matching deals) but errors are logged and skipped. The RPC returns success.
// This is the same pattern as issue #24 (silent success on all-rejected input).
func TestOutOfOrder_ProcessResponses_BeforeProcessDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	// Process deals only on nodes 1 and 2 to obtain real responses, but NOT on node 0.
	n := len(cluster.Servers)
	dealsByRecipient := buildDealsByRecipient(t, n, cluster.DealResponses)

	ctx := context.Background()
	var fabricatedResps []*pb.Response
	for i := 1; i < n; i++ {
		resp, err := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals failed for node %d", i)
		fabricatedResps = append(fabricatedResps, resp.GetResponses()...)
	}
	require.NotEmpty(t, fabricatedResps, "should have responses from nodes 1 and 2")

	// Node 0 has NOT called ProcessDeals — call ProcessResponses directly.
	// The service does not enforce call ordering: GetInitDKG creates a fresh DKG
	// (since GenerateDeals already initialized it), and ProcessResponse silently
	// skips responses that reference deals this node never processed.
	// See issue #24 for the broader "silent success on rejected input" pattern.
	_, err := cluster.Servers[0].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Responses:      fabricatedResps,
	})
	// Service currently succeeds (responses silently skipped, no ordering enforcement).
	// FinalizeDKG after this would produce an inconsistent result — but this test
	// only verifies the ProcessResponses call itself does not crash.
	require.NoError(t, err,
		"ProcessResponses currently succeeds without prior ProcessDeals "+
			"(responses are silently skipped, no ordering enforcement)")
}

// TestOutOfOrder_FinalizeDKG_CalledTwice verifies that calling FinalizeDKG a second time
// on a node that has already finalized does not corrupt state. The chain prevents this
// in production, but the kernel should handle it gracefully.
func TestOutOfOrder_FinalizeDKG_CalledTwice(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	// Record the first FinalizeDKG response for node 0
	firstResp := cluster.FinalizeResps[0]
	firstGlobalPubKey := firstResp.GetGlobalPubKey()
	firstPubKeyShare := firstResp.GetPubKeyShare()
	require.NotEmpty(t, firstGlobalPubKey, "first FinalizeDKG must return a GlobalPubKey")
	require.NotEmpty(t, firstPubKeyShare, "first FinalizeDKG must return a PubKeyShare")

	// Call FinalizeDKG AGAIN on node 0
	ctx := context.Background()
	secondResp, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.NoError(t, err, "second FinalizeDKG should succeed without error")

	// Verify deterministic output: same GlobalPubKey and PubKeyShare
	require.True(t, bytes.Equal(firstGlobalPubKey, secondResp.GetGlobalPubKey()),
		"GlobalPubKey must be identical on repeated FinalizeDKG")
	require.True(t, bytes.Equal(firstPubKeyShare, secondResp.GetPubKeyShare()),
		"PubKeyShare must be identical on repeated FinalizeDKG")

	t.Logf("Double FinalizeDKG returned consistent results: GlobalPubKey and PubKeyShare match")

	// Verify PartialDecryptTDH2 still works after double finalization
	globalPubKey := firstGlobalPubKey
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("double finalize must not break decrypt")
	label := []byte("double-finalize-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(1): result1.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(1): result1.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted,
		"PartialDecryptTDH2 must produce correct results after double FinalizeDKG")
}
