package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// TestRoundBoundary_OldRoundRejectedAfterResharing verifies that once resharing has
// completed and the latest active network has advanced to round 2, any PartialDecryptTDH2
// request referencing the old round 1 is rejected.
//
// This exercises verifyRoundMatchesLatestNetwork in dkg_partial_decrypt.go, which
// returns codes.FailedPrecondition when req.Round != latestActiveNetwork.Round.
// The test also confirms that round-2 requests are still accepted, establishing
// that the boundary is the active network round, not an arbitrary error condition.
func TestRoundBoundary_OldRoundRejectedAfterResharing(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Round 1: fresh DKG
	cluster.RunFullDKG()
	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round1GlobalPubKey)

	// Encrypt with R1 public key before resharing
	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("round boundary test")
	label := []byte("round-boundary-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Round 2: resharing — after this, latestActiveNetwork.Round == 2
	runResharingRound2(t, cluster)
	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round2GlobalPubKey)

	ctx := context.Background()

	// Round-1 request must be rejected now that latestActiveNetwork has advanced to round 2
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           round1,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    round1GlobalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err,
		"PartialDecryptTDH2 with old round must be rejected after resharing advances latestActiveNetwork")

	// Round-2 request must succeed — the R2 committee holds the same key
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, round2GlobalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey,
		map[string][]byte{NodeName(0): result0.PubShare, NodeName(1): result1.PubShare},
		ct, label,
		map[string]*mpc.TDH2PartialDecryption{NodeName(0): result0.Partial, NodeName(1): result1.Partial},
	)
	require.NoError(t, err, "round-2 partial decrypt must succeed after resharing")
	require.Equal(t, plaintext, decrypted)
}

// TestRoundBoundary_FutureRoundRejected verifies that sending a request for a round
// that hasn't been configured yet (a future round) is rejected. After completing round 1
// DKG, a GenerateDeals request for round 99 should fail because no DKG network exists
// for that round and the node has no state for it.
func TestRoundBoundary_FutureRoundRejected(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete round 1 DKG normally
	cluster.RunFullDKG()

	ctx := context.Background()

	// Explicitly configure round 99 as non-existent in the mock.
	// Without this, MockQC falls back to the default network (round 1),
	// which would not truly simulate a future round rejection.
	cluster.MockQC.SetGetDKGNetworkErrorForRound(99, fmt.Errorf("DKG network not found for round 99"))

	// Try GenerateDeals for round 99 — a future round with no network configuration.
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          99,
	})
	require.Error(t, err, "GenerateDeals for a future round (99) should fail")
	require.Contains(t, err.Error(), "roundContext",
		"error should indicate failure to load round context for the non-existent round")
}

// TestRoundCtxCache_StaleCacheUsesOldRegistrations is a regression test that documents
// the cache staleness risk. When registrations are updated via MockQC but RoundCtxCache
// is NOT reset, GenerateDeals uses the cached (stale) sorted pub keys. This causes
// different nodes to operate with different participant sets.
//
// The test proves cache staleness via two levels:
// Level 1: Direct comparison of cached SortedPubKeys between stale and fresh nodes.
// Level 2: Protocol failure — a node with fresh (tampered) registrations cannot
//
//	initialize its DKG because its own pub key is absent from the new participant list.
func TestRoundCtxCache_StaleCacheUsesOldRegistrations(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// GenerateAllKeys populates cache on all nodes with round-1 registrations
	cluster.GenerateAllKeys()

	ctx := context.Background()

	// First, populate node 0's RoundCtxCache with the CURRENT (untampered) registrations
	// by calling GenerateDeals. This caches the original pub key set.
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.NoError(t, err, "node 0 GenerateDeals should succeed (populates stale cache)")

	// Now tamper registration[2] with a valid but different Ed25519 point.
	// IMPORTANT: We must NOT mutate the existing registration pointer (shared with cached
	// RoundContext.Registrations). Instead, build a fresh registration list with the tampered key.
	regs := cluster.MockQC.GetCurrentRegistrations()

	tamperSuite := edwards25519.NewBlakeSHA256Ed25519()
	tamperScalar := tamperSuite.Scalar().Pick(tamperSuite.RandomStream())
	tamperPoint := tamperSuite.Point().Mul(tamperScalar, nil)
	tamperedPubKey, err := tamperPoint.MarshalBinary()
	require.NoError(t, err, "marshaling tampered pub key should succeed")

	// Create a deep copy of reg[2] with the tampered pub key
	tamperedReg := &pb.DKGRegistration{
		Round:         regs[2].GetRound(),
		ValidatorAddr: regs[2].GetValidatorAddr(),
		Index:         regs[2].GetIndex(),
		DkgPubKey:     tamperedPubKey,
		CommPubKey:    regs[2].GetCommPubKey(),
		Status:        regs[2].GetStatus(),
	}
	newRegs := make([]*pb.DKGRegistration, len(regs))
	copy(newRegs, regs)
	newRegs[2] = tamperedReg
	cluster.MockQC.SetRegistrations(newRegs)

	// Node 0's RoundCtxCache is STALE — it still has the original pub keys from
	// the GenerateDeals call above. We intentionally do NOT reset it.

	// Node 1: reset both RoundCtxCache AND InitDKGCache so GenerateDeals must re-fetch
	// registrations from MockQC (which now has the tampered pub key) and rebuild DKG.
	cluster.Servers[1].RoundCtxCache = store.NewRoundContextCache()
	cluster.Servers[1].InitDKGCache = store.NewDKGCache()
	_, err = cluster.Servers[1].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.NoError(t, err, "node 1 GenerateDeals should succeed with fresh cache")

	// --- Level 1: Direct proof via cached SortedPubKeys ---
	// Node 0 (stale) and node 1 (fresh) must have different pub key sets in cache.
	rc0, ok0 := cluster.Servers[0].RoundCtxCache.Get(cluster.Round)
	require.True(t, ok0, "node 0 should have cached round context")
	rc1, ok1 := cluster.Servers[1].RoundCtxCache.Get(cluster.Round)
	require.True(t, ok1, "node 1 should have cached round context")

	require.Len(t, rc0.SortedPubKeys, 3, "node 0 should have 3 sorted pub keys")
	require.Len(t, rc1.SortedPubKeys, 3, "node 1 should have 3 sorted pub keys")

	// SortedPubKeys[2] corresponds to registration Index=3 (sorted by Index, 0-based slice).
	// Node 0 (stale cache) should have the original pub key; node 1 (fresh) should have tampered.
	pub0_2, err := rc0.SortedPubKeys[2].MarshalBinary()
	require.NoError(t, err)
	pub1_2, err := rc1.SortedPubKeys[2].MarshalBinary()
	require.NoError(t, err)

	// The first two pub keys should be identical (untampered participants 0 and 1)
	pub0_0, _ := rc0.SortedPubKeys[0].MarshalBinary()
	pub1_0, _ := rc1.SortedPubKeys[0].MarshalBinary()
	require.Equal(t, pub0_0, pub1_0,
		"untampered participant 0 should be identical in stale and fresh cache")

	// The third pub key must differ — this is the tampered participant
	require.False(t, bytes.Equal(pub0_2, pub1_2),
		"stale and fresh cache nodes must see different pub keys for participant 2 "+
			"(stale has original, fresh has tampered)")

	// --- Level 2: Protocol failure proof ---
	// Node 2 with fresh (tampered) registrations cannot initialize its DKG because
	// its actual pub key (pubkey2_original) is not in the tampered participant list
	// (which contains pubkey2_tampered). kyber's NewDistKeyGenerator calls findPub()
	// which fails to find node 2's real pub key → error.
	cluster.Servers[2].RoundCtxCache = store.NewRoundContextCache()
	cluster.Servers[2].InitDKGCache = store.NewDKGCache()

	// Route node 1's deals destined for node 2
	var dealsForNode2 []*pb.Deal
	resp1, err := cluster.Servers[1].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.NoError(t, err)
	for _, d := range resp1.GetDeals() {
		if d.GetRecipientIndex() == 2 {
			dealsForNode2 = append(dealsForNode2, d)
		}
	}
	require.NotEmpty(t, dealsForNode2, "node 1 should have deals for recipient 2")

	_, err = cluster.Servers[2].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          dealsForNode2,
	})
	require.Error(t, err,
		"node 2 cannot process deals when its own pub key is not in the tampered registration set")
	t.Logf("Level 2: node 2 ProcessDeals correctly failed with tampered registrations: %v", err)
}
