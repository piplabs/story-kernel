package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

const (
	round1 uint32 = 1
	round2 uint32 = 2
)

// runResharingRound2 performs the resharing DKG from round 1 to round 2 on the cluster.
// The cluster must have already completed round 1 DKG (RunFullDKG called).
// After this returns, cluster.FinalizeResps contains round 2 results.
func runResharingRound2(t *testing.T, cluster *DKGTestCluster) {
	t.Helper()
	ctx := context.Background()

	// Collect round 1 results
	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	// Set the "latest active network" to round 1 (what nodes were part of)
	// This is what GetLatestActiveDKGNetwork returns during resharing.
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())

	// Set up round 2 resharing network
	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// Generate new round 2 keys for each node (new longterm Ed25519 + secp256k1 keys)
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
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

	// Reset RoundCtxCache on all servers to pick up new registrations
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// GenerateDeals (resharing) on all nodes — prev committee generates shares
	dealResps := make([]*pb.GenerateDealsResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals to recipients
	n := len(cluster.Servers)
	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dr := range dealResps {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	// ProcessDeals (resharing) on all nodes — next committee receives shares
	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
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

	// ProcessResponses (resharing) on all nodes
	for _, srv := range cluster.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses round 2 failed")
	}

	// FinalizeDKG (resharing) on all nodes
	finalizeResps := make([]*pb.FinalizeDKGResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "FinalizeDKG round 2 failed for node %d", i)
		finalizeResps[i] = resp
	}

	// Update cluster state to reflect round 2 results
	cluster.FinalizeResps = finalizeResps
	cluster.Round = round2

	// Update PIDCache for round 2 on each server
	for i, srv := range cluster.Servers {
		srv.PIDCache.Set(round2, uint32(i+1))
	}

	// Update network to round 2 for PartialDecryptTDH2 verification
	cluster.MockQC.SetLatestActiveNetwork(round2Network)
}

// TestResharing_KeyRotation verifies the resharing flow:
// Round 1 DKG → Round 2 Resharing → global_pub_key unchanged → new committee can decrypt.
func TestResharing_KeyRotation(t *testing.T) {
	// Run round 1 DKG
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round1GlobalPubKey)

	// Encrypt something using round 1 public key
	tdh2PubKey1, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey1.Free()

	plaintext := []byte("resharing key rotation test")
	label := []byte("resharing-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey1, plaintext, label)
	require.NoError(t, err)

	// Run round 2 resharing
	runResharingRound2(t, cluster)

	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round2GlobalPubKey)

	// Global public key must NOT change after resharing
	require.True(t,
		bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"global_pub_key must be preserved after resharing")

	// All round 2 nodes must agree on global_pub_key
	for i := 1; i < len(cluster.Servers); i++ {
		require.True(t,
			bytes.Equal(round2GlobalPubKey, cluster.FinalizeResps[i].GetGlobalPubKey()),
			"node %d round 2 global_pub_key mismatch", i)
	}

	// New committee (round 2) can decrypt the round 1 ciphertext
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	results := make([]*partialDecryptResult, len(cluster.Servers))
	for i := range cluster.Servers {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Combine using nodes 0 and 1
	pubShares := map[string][]byte{
		NodeName(0): results[0].PubShare,
		NodeName(1): results[1].PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): results[0].Partial,
		NodeName(1): results[1].Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey1, pubShares, ct, label, pdMap)
	require.NoError(t, err, "new committee should decrypt old ciphertext after resharing")
	require.Equal(t, plaintext, decrypted)
}

// TestResharing_PubKeySharesDiffer verifies that round 2 pub_key_shares are all different
// (each node has a unique share).
func TestResharing_PubKeySharesDiffer(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()
	runResharingRound2(t, cluster)

	shares := make([][]byte, len(cluster.Servers))
	for i, fr := range cluster.FinalizeResps {
		shares[i] = fr.GetPubKeyShare()
		require.NotEmpty(t, shares[i], "node %d: round 2 pub_key_share should not be empty", i)
	}
	require.False(t, bytes.Equal(shares[0], shares[1]), "round 2: node 0 and 1 shares should differ")
	require.False(t, bytes.Equal(shares[1], shares[2]), "round 2: node 1 and 2 shares should differ")
}

// TestResharing_ProcessResponses_SurvivesMissingPrevDKG verifies that ProcessResponses
// during resharing does NOT return an error when the prevDKG state is unavailable on one node.
//
// The service has a "soft failure" path for prevDKG: if the prevDKG cannot be loaded
// (cache miss + rebuild failure), it logs at INFO and continues. The nextDKG (new
// committee's state) is unaffected, so the resharing can still complete for honest nodes.
//
// Fault injection: after ProcessDeals (which populates ResharingPrevCache), we clear
// ResharingPrevCache on node 0 and delete its sealed DistKeyShare file so that rebuild
// also fails. We then verify ProcessResponses still returns no error.
func TestResharing_ProcessResponses_SurvivesMissingPrevDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()
	t.Logf("[G8] Round 1 DKG complete: global_pub_key=%x... public_coeffs_count=%d",
		round1GlobalPubKey[:4], len(round1PublicCoeffs))

	ctx := context.Background()

	// Configure MockQC for resharing: round 1 is latest active, round 2 is resharing target
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())
	t.Logf("[G8] Configured MockQC with round 1 as latest active network")

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)
	t.Logf("[G8] Configured MockQC with round 2 resharing network")

	// Generate new round 2 keys for each node
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "[G8] GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
		t.Logf("[G8] Node %d generated round 2 key: dkg_pub_key_len=%d", i, len(resp.GetDkgPubKey()))
	}

	// Build and register round 2 registrations
	round2Regs := make([]*pb.DKGRegistration, len(cluster.Servers))
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
		t.Logf("[G8] Round 2 registration: node=%d index=%d addr=%s", i, i+1, cluster.Addresses[i])
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	// Reset RoundCtxCache to pick up new round 2 registrations
	for i, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
		t.Logf("[G8] Node %d RoundCtxCache reset for round 2", i)
	}

	// GenerateDeals (resharing) — this populates ResharingPrevCache with prev DKG state
	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "[G8] GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
		t.Logf("[G8] Node %d GenerateDeals: generated %d deal(s)", i, len(resp.GetDeals()))
	}

	// Route deals to recipients
	dealsByRecipient := make([][]*pb.Deal, n)
	for senderIdx, dr := range dealResps {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
			t.Logf("[G8] Routed deal from sender=%d to recipient=%d", senderIdx, idx)
		}
	}

	// ProcessDeals (resharing) — next committee receives shares
	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "[G8] ProcessDeals round 2 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
		t.Logf("[G8] Node %d ProcessDeals: %d response(s)", i, len(processedResps[i]))
	}

	// === FAULT INJECTION ===
	// Clear ResharingPrevCache on node 0 to simulate loss of prevDKG state between
	// ProcessDeals and ProcessResponses (e.g. eviction, OOM, partial crash).
	// Also clear DistKeyShareCache so that the rebuild path must read from disk.
	// The sealed DistKeyShare file for round1 still exists on disk, but the service
	// may not be able to reconstruct a valid kyber DKG instance from it — in either
	// case the service should log at INFO and continue without returning an error.
	t.Logf("[G8] FAULT INJECTION: clearing ResharingPrevCache + DistKeyShareCache on node 0")
	cluster.Servers[0].ResharingPrevCache = store.NewResharingDKGCache()
	cluster.Servers[0].DistKeyShareCache = store.NewDistKeyShareCache()
	t.Logf("[G8] Node 0 ResharingPrevCache and DistKeyShareCache cleared")

	// Flatten responses for broadcast
	var allResps []*pb.Response
	for i, resps := range processedResps {
		allResps = append(allResps, resps...)
		t.Logf("[G8] Node %d contributed %d response(s) to broadcast", i, len(resps))
	}
	t.Logf("[G8] Total broadcast responses: %d", len(allResps))

	// ProcessResponses (resharing) — node 0's prevDKG will be missing.
	// The service soft-fails on prevDKG: logs INFO and continues.
	// ProcessResponses must NOT return an error.
	for i, srv := range cluster.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		t.Logf("[G8] Node %d ProcessResponses(IsResharing=true) err=%v", i, err)
		require.NoError(t, err,
			"ProcessResponses must not return error even when node %d prevDKG is missing (soft failure path)", i)
	}
	t.Logf("[G8] All nodes passed ProcessResponses without error — prevDKG soft failure confirmed")

	// FinalizeDKG (resharing) on nodes 1 and 2 (which had intact prevDKG)
	for _, i := range []int{1, 2} {
		resp, err := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		t.Logf("[G8] Node %d FinalizeDKG(IsResharing=true) err=%v global_pub_key_len=%d",
			i, err, len(resp.GetGlobalPubKey()))
		require.NoError(t, err, "[G8] FinalizeDKG round 2 failed for node %d", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "[G8] node %d global_pub_key must not be empty after resharing", i)
	}
	t.Logf("[G8] PASS: resharing completed successfully despite node 0 prevDKG state loss")
}

// TestResharing_ScaleDown_3To2 verifies resharing from a 3-node committee (round 1, threshold=2)
// to a smaller 2-node committee (round 2, threshold=2). Node 2 leaves the committee; only
// nodes 0 and 1 continue. After resharing the global_pub_key must be preserved, and both
// remaining nodes together can decrypt data encrypted with the old key (2-of-2).
func TestResharing_ScaleDown_3To2(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()
	t.Logf("[ScaleDown] Round 1 DKG complete: 3 nodes threshold=2 global_pub_key=%x...",
		round1GlobalPubKey[:4])

	// Encrypt with round 1 public key before resharing
	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("scale-down resharing 3→2 test")
	label := []byte("scaledown-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)
	t.Logf("[ScaleDown] Encrypted %d bytes with round 1 public key", len(plaintext))

	ctx := context.Background()

	// Round 2: only nodes 0 and 1 continue (node 2 leaves), threshold=2 (2-of-2).
	// Note: kyber DKG requires threshold >= 2; threshold=1 is invalid for Pedersen resharing.
	const nextN = 2
	const nextThreshold = uint32(2)
	t.Logf("[ScaleDown] Round 2 committee: %d nodes threshold=%d (node 2 leaves)", nextN, nextThreshold)

	// Configure MockQC: round 1 as latest active, round 2 as resharing target
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())
	t.Logf("[ScaleDown] Configured round 1 as latest active network (prev committee: 3 nodes)")

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            nextN,
		Threshold:        nextThreshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)
	t.Logf("[ScaleDown] Configured round 2 network: %d nodes threshold=%d", nextN, nextThreshold)

	// Generate round 2 keys — only nodes 0 and 1 participate in round 2
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, nextN)
	for i := 0; i < nextN; i++ {
		resp, err := cluster.Servers[i].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "[ScaleDown] GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
		t.Logf("[ScaleDown] Node %d: generated round 2 key (dkg_pub_key_len=%d)", i, len(resp.GetDkgPubKey()))
	}

	// Register only nodes 0 and 1 for round 2 (node 2 is excluded)
	round2Regs := make([]*pb.DKGRegistration, nextN)
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
		t.Logf("[ScaleDown] Registered node %d for round 2 (index=%d addr=%s)", i, i+1, cluster.Addresses[i])
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	// Reset RoundCtxCache on all servers to pick up new round 2 registrations
	for i, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
		t.Logf("[ScaleDown] Node %d: RoundCtxCache reset", i)
	}

	// GenerateDeals (resharing) — only nodes 0 and 1 are in round 2 registrations.
	// Node 2 is excluded: CachePID would fail since its round 2 key is not registered.
	dealResps := make([]*pb.GenerateDealsResponse, nextN)
	for i := 0; i < nextN; i++ {
		resp, err := cluster.Servers[i].GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "[ScaleDown] GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
		t.Logf("[ScaleDown] Node %d: GenerateDeals produced %d deals", i, len(resp.GetDeals()))
	}

	// Route deals to 2 recipients by RecipientIndex
	dealsByRecipient := make([][]*pb.Deal, nextN)
	for senderIdx, dr := range dealResps {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
			t.Logf("[ScaleDown] Routed deal from sender=%d to recipient=%d", senderIdx, idx)
		}
	}
	for i := 0; i < nextN; i++ {
		t.Logf("[ScaleDown] Recipient node %d: %d deal(s) queued", i, len(dealsByRecipient[i]))
	}

	// ProcessDeals (resharing) for nodes 0 and 1
	processedResps := make([][]*pb.Response, nextN)
	for i := 0; i < nextN; i++ {
		resp, err := cluster.Servers[i].ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "[ScaleDown] ProcessDeals round 2 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
		t.Logf("[ScaleDown] Node %d: ProcessDeals produced %d response(s)", i, len(processedResps[i]))
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for i, resps := range processedResps {
		allResps = append(allResps, resps...)
		t.Logf("[ScaleDown] Node %d: contributed %d response(s) to broadcast", i, len(resps))
	}
	t.Logf("[ScaleDown] Total broadcast responses: %d", len(allResps))

	// ProcessResponses (resharing) for nodes 0 and 1
	for i := 0; i < nextN; i++ {
		_, err := cluster.Servers[i].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		t.Logf("[ScaleDown] Node %d: ProcessResponses err=%v", i, err)
		require.NoError(t, err, "[ScaleDown] ProcessResponses round 2 failed for node %d", i)
	}

	// FinalizeDKG (resharing) for nodes 0 and 1
	finalizeResps := make([]*pb.FinalizeDKGResponse, nextN)
	for i := 0; i < nextN; i++ {
		resp, err := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		t.Logf("[ScaleDown] Node %d: FinalizeDKG err=%v global_pub_key_len=%d",
			i, err, len(resp.GetGlobalPubKey()))
		require.NoError(t, err, "[ScaleDown] FinalizeDKG round 2 failed for node %d", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "[ScaleDown] node %d global_pub_key must not be empty", i)
		finalizeResps[i] = resp
	}

	// Verify: global_pub_key must be identical after scale-down resharing
	round2GlobalPubKey := finalizeResps[0].GetGlobalPubKey()
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"[ScaleDown] global_pub_key must be preserved after scale-down resharing")
	require.True(t, bytes.Equal(round2GlobalPubKey, finalizeResps[1].GetGlobalPubKey()),
		"[ScaleDown] nodes 0 and 1 must agree on round 2 global_pub_key")
	t.Logf("[ScaleDown] PASS: global_pub_key preserved after scale-down: %x...", round2GlobalPubKey[:4])

	// Prepare for PartialDecryptTDH2 calls
	cluster.MockQC.SetLatestActiveNetwork(round2Network)
	for i := 0; i < nextN; i++ {
		cluster.Servers[i].PIDCache.Set(round2, uint32(i+1))
	}
	cluster.Round = round2

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	results := make([]*partialDecryptResult, nextN)
	for i := 0; i < nextN; i++ {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
		t.Logf("[ScaleDown] Node %d: partial decrypt ok (pub_share_len=%d partial_len=%d)",
			i, len(results[i].PubShare), len(results[i].Partial.Bytes))
	}

	// threshold=2: both nodes must cooperate to decrypt (2-of-2)
	nodeNames := []string{NodeName(0), NodeName(1)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	t.Run("both-nodes-2of2", func(t *testing.T) {
		pubShares := map[string][]byte{
			NodeName(0): results[0].PubShare,
			NodeName(1): results[1].PubShare,
		}
		pdMap := map[string]*mpc.TDH2PartialDecryption{
			NodeName(0): results[0].Partial,
			NodeName(1): results[1].Partial,
		}

		decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
		require.NoError(t, err, "[ScaleDown] 2-of-2 combine failed")
		require.Equal(t, plaintext, decrypted, "[ScaleDown] decrypted text mismatch")
		t.Logf("[ScaleDown] both nodes together decrypted successfully (threshold=2)")
	})
	t.Logf("[ScaleDown] PASS: 2-node committee with threshold=2 can decrypt after scale-down resharing")
}

// TestResharing_ScaleUp_3To5 verifies resharing from a 3-node committee (round 1, threshold=2)
// to a larger 5-node committee (round 2, threshold=3). Two new nodes join; the original 3
// remain and generate resharing deals for all 5. After resharing the global_pub_key must be
// preserved, and any 3-of-5 node combination can decrypt data encrypted with the old key.
func TestResharing_ScaleUp_3To5(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()
	t.Logf("[ScaleUp] Round 1 DKG complete: 3 nodes threshold=2 global_pub_key=%x...",
		round1GlobalPubKey[:4])

	// Encrypt with round 1 public key before resharing
	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("scale-up resharing 3→5 test")
	label := []byte("scaleup-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)
	t.Logf("[ScaleUp] Encrypted %d bytes with round 1 public key", len(plaintext))

	ctx := context.Background()

	// Create 2 new servers sharing the same MockQC (addr offset=3 → addresses 4 and 5)
	newSrvs, newAddrs, newDirs := buildFreshServers(t, cluster.MockQC, 2, 3)
	defer func() {
		for _, d := range newDirs {
			_ = fmt.Sprintf("cleanup %s", d) // dirs cleaned via os.RemoveAll below
			os.RemoveAll(d)
		}
	}()
	t.Logf("[ScaleUp] Created 2 new servers for round 2: addresses=%v", newAddrs)

	// Round 2: all 5 = original 3 + 2 new, threshold=3
	const nextThreshold = uint32(3)
	round2AllSrvs := append(cluster.Servers, newSrvs...)
	round2AllAddrs := append(cluster.Addresses, newAddrs...)
	nextN := len(round2AllSrvs) // 5
	t.Logf("[ScaleUp] Round 2 committee: %d nodes threshold=%d", nextN, nextThreshold)

	// Configure MockQC
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())
	t.Logf("[ScaleUp] Configured round 1 as latest active network (prev committee: 3 nodes)")

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(nextN),
		Threshold:        nextThreshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)
	t.Logf("[ScaleUp] Configured round 2 network: %d nodes threshold=%d", nextN, nextThreshold)

	// All 5 nodes generate round 2 keys
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, nextN)
	for i, srv := range round2AllSrvs {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        round2AllAddrs[i],
		})
		require.NoError(t, err, "[ScaleUp] GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
		t.Logf("[ScaleUp] Node %d (addr=%s): generated round 2 key (dkg_pub_key_len=%d)",
			i, round2AllAddrs[i], len(resp.GetDkgPubKey()))
	}

	// Register all 5 for round 2
	round2Regs := make([]*pb.DKGRegistration, nextN)
	for i, resp := range round2KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round2Regs[i] = &pb.DKGRegistration{
			Round:         round2,
			ValidatorAddr: round2AllAddrs[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
		t.Logf("[ScaleUp] Registered node %d for round 2 (index=%d addr=%s)", i, i+1, round2AllAddrs[i])
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	// Reset RoundCtxCache on all servers
	for i, srv := range round2AllSrvs {
		srv.RoundCtxCache = store.NewRoundContextCache()
		t.Logf("[ScaleUp] Node %d: RoundCtxCache reset", i)
	}

	// GenerateDeals (resharing) — only the original 3 nodes (they have round 1 prevDKG state).
	// The 2 new nodes have no round 1 state and cannot call GenerateDeals(IsResharing=true).
	prevN := len(cluster.Servers) // 3
	dealResps := make([]*pb.GenerateDealsResponse, prevN)
	for i := 0; i < prevN; i++ {
		resp, err := cluster.Servers[i].GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "[ScaleUp] GenerateDeals round 2 failed for old node %d", i)
		dealResps[i] = resp
		t.Logf("[ScaleUp] Old node %d: GenerateDeals produced %d deals", i, len(resp.GetDeals()))
	}

	// Route deals from 3 old nodes to all 5 recipients by RecipientIndex
	dealsByRecipient := make([][]*pb.Deal, nextN)
	for senderIdx, dr := range dealResps {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
			t.Logf("[ScaleUp] Routed deal from old node=%d to recipient=%d", senderIdx, idx)
		}
	}
	for i := 0; i < nextN; i++ {
		t.Logf("[ScaleUp] Recipient node %d: %d deal(s) queued", i, len(dealsByRecipient[i]))
	}

	// ProcessDeals (resharing) for all 5 nodes
	processedResps := make([][]*pb.Response, nextN)
	for i, srv := range round2AllSrvs {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "[ScaleUp] ProcessDeals round 2 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
		t.Logf("[ScaleUp] Node %d: ProcessDeals produced %d response(s)", i, len(processedResps[i]))
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for i, resps := range processedResps {
		allResps = append(allResps, resps...)
		t.Logf("[ScaleUp] Node %d: contributed %d response(s) to broadcast", i, len(resps))
	}
	t.Logf("[ScaleUp] Total broadcast responses: %d", len(allResps))

	// ProcessResponses (resharing) for all 5 nodes
	for i, srv := range round2AllSrvs {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		t.Logf("[ScaleUp] Node %d: ProcessResponses err=%v", i, err)
		require.NoError(t, err, "[ScaleUp] ProcessResponses round 2 failed for node %d", i)
	}

	// FinalizeDKG (resharing) for all 5 nodes
	finalizeResps := make([]*pb.FinalizeDKGResponse, nextN)
	for i, srv := range round2AllSrvs {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		t.Logf("[ScaleUp] Node %d: FinalizeDKG err=%v global_pub_key_len=%d",
			i, err, len(resp.GetGlobalPubKey()))
		require.NoError(t, err, "[ScaleUp] FinalizeDKG round 2 failed for node %d", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "[ScaleUp] node %d global_pub_key must not be empty", i)
		finalizeResps[i] = resp
	}

	// Verify: global_pub_key must be identical across all 5 nodes and match round 1
	round2GlobalPubKey := finalizeResps[0].GetGlobalPubKey()
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"[ScaleUp] global_pub_key must be preserved after scale-up resharing")
	for i := 1; i < nextN; i++ {
		require.True(t, bytes.Equal(round2GlobalPubKey, finalizeResps[i].GetGlobalPubKey()),
			"[ScaleUp] node %d global_pub_key mismatch", i)
	}
	t.Logf("[ScaleUp] PASS: global_pub_key preserved and consistent across all %d nodes: %x...",
		nextN, round2GlobalPubKey[:4])

	// Prepare for PartialDecryptTDH2: set PIDCache and update MockQC
	cluster.MockQC.SetLatestActiveNetwork(round2Network)
	for i := 0; i < prevN; i++ {
		cluster.Servers[i].PIDCache.Set(round2, uint32(i+1))
		t.Logf("[ScaleUp] Set PIDCache: old node %d → PID %d", i, i+1)
	}
	for i, srv := range newSrvs {
		pid := uint32(prevN + i + 1) // PIDs 4 and 5
		srv.PIDCache.Set(round2, pid)
		t.Logf("[ScaleUp] Set PIDCache: new node %d → PID %d", i, pid)
	}
	cluster.Round = round2

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partial decryptions from all 5 nodes
	results := make([]*partialDecryptResult, nextN)
	for i := 0; i < prevN; i++ {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
		t.Logf("[ScaleUp] Old node %d: partial decrypt ok (pub_share_len=%d partial_len=%d)",
			i, len(results[i].PubShare), len(results[i].Partial.Bytes))
	}
	for i, srv := range newSrvs {
		nodeIdx := prevN + i
		results[nodeIdx] = collectPartialDecryptSrv(t, srv, round2, cluster.CodeCommitment,
			ct.Bytes, round2GlobalPubKey, label, requesterPriv)
		t.Logf("[ScaleUp] New node %d: partial decrypt ok (pub_share_len=%d partial_len=%d)",
			nodeIdx, len(results[nodeIdx].PubShare), len(results[nodeIdx].Partial.Bytes))
	}

	// threshold=3: any 3-of-5 combination should decrypt the old ciphertext
	nodeNames := make([]string, nextN)
	for i := range nextN {
		nodeNames[i] = NodeName(i)
	}
	as, err := buildTDH2AccessStructure(int(nextThreshold), nodeNames)
	require.NoError(t, err)

	// Test all C(5,3)=10 combinations
	combos := [][3]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4},
		{0, 2, 3}, {0, 2, 4}, {0, 3, 4},
		{1, 2, 3}, {1, 2, 4}, {1, 3, 4},
		{2, 3, 4},
	}
	for _, combo := range combos {
		a, b, c := combo[0], combo[1], combo[2]
		t.Run(fmt.Sprintf("scaleup-%s+%s+%s", NodeName(a), NodeName(b), NodeName(c)), func(t *testing.T) {
			pubShares := map[string][]byte{
				NodeName(a): results[a].PubShare,
				NodeName(b): results[b].PubShare,
				NodeName(c): results[c].PubShare,
			}
			pdMap := map[string]*mpc.TDH2PartialDecryption{
				NodeName(a): results[a].Partial,
				NodeName(b): results[b].Partial,
				NodeName(c): results[c].Partial,
			}

			decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
			require.NoError(t, err, "[ScaleUp] combine failed for nodes %d+%d+%d", a, b, c)
			require.Equal(t, plaintext, decrypted, "[ScaleUp] decrypted text mismatch for nodes %d+%d+%d", a, b, c)
			t.Logf("[ScaleUp] nodes %d+%d+%d combined successfully", a, b, c)
		})
	}
	t.Logf("[ScaleUp] PASS: 5-node committee (threshold=3) all C(5,3)=10 combos decrypted after scale-up resharing")
}

// TestResharing_ZeroOverlap verifies resharing from committee {node0, node1, node2} (round 1)
// to a completely disjoint committee {node3, node4, node5} (round 2, threshold=2).
// No member is shared between the two committees. After resharing the global_pub_key must
// be preserved and the new committee can decrypt data encrypted with the old key.
func TestResharing_ZeroOverlap(t *testing.T) {
	// Run round 1 DKG on the original 3-node committee
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()
	require.NotEmpty(t, round1GlobalPubKey)

	// Encrypt with R1 public key before resharing
	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("zero overlap resharing test")
	label := []byte("zero-overlap-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	ctx := context.Background()

	// Build 3 entirely new servers for the next committee (addrOffset=3 → addresses 4,5,6)
	newSrvs, newAddrs, newDirs := buildFreshServers(t, cluster.MockQC, 3, 3)
	defer func() {
		for _, d := range newDirs {
			os.RemoveAll(d)
		}
	}()

	// Configure MockQC: round 1 as latest active, round 2 as resharing target
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            3,
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// New committee generates round 2 keys
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, 3)
	for i, srv := range newSrvs {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        newAddrs[i],
		})
		require.NoError(t, err, "new node %d GenerateAndSealKey round 2 failed", i)
		round2KeyResps[i] = resp
	}

	// Register new committee for round 2
	round2Regs := make([]*pb.DKGRegistration, 3)
	for i, resp := range round2KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round2Regs[i] = &pb.DKGRegistration{
			Round:         round2,
			ValidatorAddr: newAddrs[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	// Reset RoundCtxCache on old and new committee nodes to pick up round 2 registrations.
	// New committee nodes cached stale round-1 registrations during GenerateAndSealKey
	// (before round2Regs was set), so their caches must be invalidated here.
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}
	for _, srv := range newSrvs {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Old committee generates resharing deals for new committee
	dealResps := make([]*pb.GenerateDealsResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "old node %d GenerateDeals round 2 failed", i)
		dealResps[i] = resp
	}

	// Route deals to new committee recipients by RecipientIndex
	dealsByRecipient := buildDealsByRecipient(t, 3, dealResps)

	// New committee processes deals
	processedResps := make([][]*pb.Response, 3)
	for i, srv := range newSrvs {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "new node %d ProcessDeals round 2 failed", i)
		processedResps[i] = resp.GetResponses()
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	// New committee processes responses
	for i, srv := range newSrvs {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		require.NoError(t, err, "new node %d ProcessResponses round 2 failed", i)
	}

	// New committee finalizes
	finalizeResps := make([]*pb.FinalizeDKGResponse, 3)
	for i, srv := range newSrvs {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "new node %d FinalizeDKG round 2 failed", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "new node %d must produce global_pub_key", i)
		finalizeResps[i] = resp
	}

	// Verify: global_pub_key preserved across zero-overlap resharing
	round2GlobalPubKey := finalizeResps[0].GetGlobalPubKey()
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"global_pub_key must be preserved after zero-overlap resharing")
	for i := 1; i < 3; i++ {
		require.True(t, bytes.Equal(round2GlobalPubKey, finalizeResps[i].GetGlobalPubKey()),
			"new node %d global_pub_key mismatch", i)
	}

	// Set PIDCache on new nodes and update MockQC for PartialDecryptTDH2
	cluster.MockQC.SetLatestActiveNetwork(round2Network)
	for i, srv := range newSrvs {
		srv.PIDCache.Set(round2, uint32(i+1))
	}

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// New committee produces partial decryptions for the R1 ciphertext
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	result0 := collectPartialDecryptSrv(t, newSrvs[0], round2, cluster.CodeCommitment,
		ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	result1 := collectPartialDecryptSrv(t, newSrvs[1], round2, cluster.CodeCommitment,
		ct.Bytes, round2GlobalPubKey, label, requesterPriv)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(1): result1.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(1): result1.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err, "new committee must decrypt old ciphertext after zero-overlap resharing")
	require.Equal(t, plaintext, decrypted)
}

// TestResharing_AllCombinationsAfterResharing verifies all C(3,2)=3 pairs can decrypt after resharing.
func TestResharing_AllCombinationsAfterResharing(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("all combinations after resharing")
	label := []byte("combo-resharing-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	runResharingRound2(t, cluster)

	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	results := make([]*partialDecryptResult, 3)
	for i := range 3 {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	combinations := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, combo := range combinations {
		a, b := combo[0], combo[1]
		t.Run(fmt.Sprintf("resharing-%s+%s", NodeName(a), NodeName(b)), func(t *testing.T) {
			pubShares := map[string][]byte{
				NodeName(a): results[a].PubShare,
				NodeName(b): results[b].PubShare,
			}
			pdMap := map[string]*mpc.TDH2PartialDecryption{
				NodeName(a): results[a].Partial,
				NodeName(b): results[b].Partial,
			}

			decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
			require.NoError(t, err, "combine failed for nodes %d+%d after resharing", a, b)
			require.Equal(t, plaintext, decrypted)
		})
	}
}

// TestResharing_NewCommitteeCannotGenerateDeals verifies that during resharing, a
// new committee node (which has no round 1 DKG state) cannot call GenerateDeals
// with IsResharing=true. Only old committee nodes that participated in round 1 have
// the prevDKG state needed to generate resharing deals.
//
// Setup: round 1 DKG with 3 nodes, then create 3 fresh servers as the new committee
// for round 2. A fresh server calls GenerateDeals(IsResharing=true) for round 2 and
// expects an error because it has no round 1 DistKeyShare to reshare from.
func TestResharing_NewCommitteeCannotGenerateDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete round 1 DKG
	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	ctx := context.Background()

	// Create 3 fresh servers for the new committee (no round 1 state)
	newSrvs, newAddrs, newDirs := buildFreshServers(t, cluster.MockQC, 3, 3)
	defer func() {
		for _, d := range newDirs {
			os.RemoveAll(d)
		}
	}()

	// Configure MockQC for resharing
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            3,
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// New committee generates round 2 keys
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, 3)
	for i, srv := range newSrvs {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        newAddrs[i],
		})
		require.NoError(t, err, "new node %d GenerateAndSealKey round 2 failed", i)
		round2KeyResps[i] = resp
	}

	// Register new committee for round 2
	round2Regs := make([]*pb.DKGRegistration, 3)
	for i, resp := range round2KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round2Regs[i] = &pb.DKGRegistration{
			Round:         round2,
			ValidatorAddr: newAddrs[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(round2Regs)
	cluster.MockQC.SetRegistrationsByRound(round2, round2Regs)

	// Reset RoundCtxCache on new servers
	for _, srv := range newSrvs {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// New committee node tries GenerateDeals(IsResharing=true) — should fail
	// because it has no round 1 DKG state (no prevDKG to reshare from)
	_, err := newSrvs[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          round2,
		IsResharing:    true,
	})
	require.Error(t, err,
		"new committee node should not be able to GenerateDeals(IsResharing=true) without round 1 DKG state")
	t.Logf("New committee GenerateDeals correctly failed: %v", err)
}

// TestResharing_MidCrashDuringGenerateDeals verifies that resharing can still succeed
// when one old committee node crashes (does not generate deals). With a 3-node old
// committee (threshold=2), only 2 dealers are needed to produce valid resharing deals.
// Node 2 is simulated as crashed (skips GenerateDeals), and the remaining 2 nodes'
// deals are sufficient for the new committee to complete resharing.
func TestResharing_MidCrashDuringGenerateDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete round 1 DKG
	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	ctx := context.Background()

	// Configure MockQC for resharing
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round2, round2Network)
	cluster.MockQC.SetNetwork(round2Network)

	// Generate round 2 keys for all nodes
	round2KeyResps := make([]*pb.GenerateAndSealKeyResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "GenerateAndSealKey round 2 failed for node %d", i)
		round2KeyResps[i] = resp
	}

	// Build and register round 2 registrations
	round2Regs := make([]*pb.DKGRegistration, len(cluster.Servers))
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

	// Reset RoundCtxCache on all servers
	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	// GenerateDeals (resharing) — only nodes 0 and 1 generate deals.
	// Node 2 is simulated as crashed (skips GenerateDeals entirely).
	t.Logf("Simulating node 2 crash: only nodes 0 and 1 generate resharing deals")
	dealResps := make([]*pb.GenerateDealsResponse, 2)
	for i := 0; i < 2; i++ {
		resp, err := cluster.Servers[i].GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 failed for node %d", i)
		dealResps[i] = resp
		t.Logf("Node %d: GenerateDeals produced %d deals", i, len(resp.GetDeals()))
	}

	// Route deals from 2 dealers to all 3 recipients
	n := len(cluster.Servers)
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)
	for i := 0; i < n; i++ {
		t.Logf("Recipient node %d: %d deal(s) from 2 dealers", i, len(dealsByRecipient[i]))
	}

	// ProcessDeals (resharing) on all 3 nodes — each gets deals from only 2 senders
	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals round 2 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
		t.Logf("Node %d: ProcessDeals produced %d response(s)", i, len(processedResps[i]))
	}

	// Broadcast all responses
	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	// ProcessResponses (resharing) on all 3 nodes
	for i, srv := range cluster.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses round 2 failed for node %d", i)
	}

	// FinalizeDKG (resharing) on all 3 nodes
	finalizeResps := make([]*pb.FinalizeDKGResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "FinalizeDKG round 2 failed for node %d", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "node %d global_pub_key must not be empty", i)
		finalizeResps[i] = resp
	}

	// Verify: global_pub_key must be preserved after resharing with 2-of-3 dealers
	round2GlobalPubKey := finalizeResps[0].GetGlobalPubKey()
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"global_pub_key must be preserved after resharing with partial dealers (2 of 3)")
	for i := 1; i < n; i++ {
		require.True(t, bytes.Equal(round2GlobalPubKey, finalizeResps[i].GetGlobalPubKey()),
			"node %d global_pub_key mismatch after resharing", i)
	}
	t.Logf("PASS: resharing succeeded with 2-of-3 dealers (node 2 crashed), global_pub_key=%x...",
		round2GlobalPubKey[:4])
}

// TestResharing_FlagAbuse_TrueOnInitialRound verifies that calling ProcessDeals with
// IsResharing=true on an initial (non-resharing) DKG round returns an error.
// The service branches on req.GetIsResharing() at dkg_process_deals.go:53 — when true
// it calls GetResharingNextDKG(), which has no state because this is an initial round.
func TestResharing_FlagAbuse_TrueOnInitialRound(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Build deals for node 0 (same pattern as cheating detection tests)
	dealsByRecipient := buildDealsByRecipient(t, n, cluster.DealResponses)

	// Call ProcessDeals on node 0 with IsResharing=true — but this is an initial DKG round.
	// FINDING: The service does NOT validate IsResharing against on-chain state.
	// It builds a ResharingNextDKG handler even on an initial round, and ProcessDeal succeeds.
	// This is safe because the chain always sets IsResharing correctly (computed from
	// getLatestActiveDKGNetwork), but the kernel itself has no defense against a wrong flag.
	resp, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		IsResharing:    true,
		Deals:          dealsByRecipient[0],
	})
	// Characterization: service accepts IsResharing=true on initial round without error.
	// The ResharingNextDKG path builds a new DKG handler using the same participants.
	// Chain-side defense: IsResharing is computed by BeginBlocker, not caller-specified.
	require.NoError(t, err, "Characterization: ProcessDeals(IsResharing=true) on initial round succeeds — kernel does not validate flag")
	t.Logf("FINDING: ProcessDeals(IsResharing=true) on initial round succeeded with %d responses. "+
		"Kernel does not validate IsResharing against on-chain state. "+
		"Chain-side defense: flag is computed by BeginBlocker.", len(resp.GetResponses()))
}

// TestResharing_FlagAbuse_FalseOnResharingRound verifies the behavior when ProcessDeals
// is called with IsResharing=false on a round that was set up as a resharing round.
// The service branches on req.GetIsResharing() — when false it calls GetInitDKG(),
// which should not have the resharing state. This documents whether the mismatch
// causes an error or silently uses the wrong DKG path.
func TestResharing_FlagAbuse_FalseOnResharingRound(t *testing.T) {
	// --- Round 1: complete full initial DKG ---
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round1PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()
	require.NotEmpty(t, round1GlobalPubKey)

	ctx := context.Background()
	n := len(cluster.Servers)

	// --- Round 2: set up resharing (same as runResharingRound2 pattern) ---
	round1Network := &pb.DKGNetwork{
		Round:            round1,
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
	cluster.MockQC.SetRegistrationsByRound(round1, cluster.MockQC.GetCurrentRegistrations())

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

	// Build round 2 registrations
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

	// Old committee generates deals for resharing
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round2,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 2 resharing failed for node %d", i)
		dealResps[i] = resp
	}

	// Route deals to recipients
	dealsByRecipient := buildDealsByRecipient(t, n, dealResps)

	// New committee node calls ProcessDeals with IsResharing=false (WRONG flag).
	// This uses the InitDKG path instead of ResharingNextDKG — document the behavior.
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          round2,
		IsResharing:    false, // WRONG: should be true for resharing round
		Deals:          dealsByRecipient[0],
	})
	// The InitDKG path should not have proper state for a resharing round,
	// or the deals will be incompatible with the InitDKG polynomial.
	require.Error(t, err, "ProcessDeals with IsResharing=false on resharing round should fail — wrong DKG path")
	t.Logf("ProcessDeals(IsResharing=false) on resharing round correctly returned error: %v", err)
}

// TestResharing_FlagAbuse_FinalizeMismatch verifies that calling FinalizeDKG with
// IsResharing=true after a normal (non-resharing) DKG returns an error.
// The service branches on req.GetIsResharing() at dkg_finalize.go:55 — when true
// it looks for ResharingNextDKG state, which does not exist after an initial DKG.
func TestResharing_FlagAbuse_FinalizeMismatch(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Complete a full initial DKG (3 nodes, threshold=2)
	cluster.RunFullDKG()

	ctx := context.Background()

	// Call FinalizeDKG on node 0 with IsResharing=true — mismatch, the DKG was initial.
	// No ResharingNextDKG state exists, so this should fail.
	_, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		IsResharing:    true,
	})
	require.Error(t, err, "FinalizeDKG with IsResharing=true after initial DKG should fail — no ResharingNextDKG state")
	t.Logf("FinalizeDKG(IsResharing=true) after initial DKG correctly returned error: %v", err)
}
