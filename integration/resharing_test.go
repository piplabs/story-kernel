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
		CodeCommitment:   cluster.CodeCommitment,
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
		CodeCommitment:   cluster.CodeCommitment,
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


