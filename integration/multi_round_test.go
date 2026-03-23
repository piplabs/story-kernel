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

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

const round3 uint32 = 3

// runResharingRound3 performs the resharing DKG from round 2 to round 3 on the cluster.
// The cluster must have already completed round 2 resharing (runResharingRound2 called).
// After this returns, cluster.FinalizeResps contains round 3 results.
func runResharingRound3(t *testing.T, cluster *DKGTestCluster) {
	t.Helper()
	ctx := context.Background()

	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	round2PublicCoeffs := cluster.FinalizeResps[0].GetPublicCoeffs()

	round2Network := &pb.DKGNetwork{
		Round:            round2,
		StartBlockHeight: 200,
		StartBlockHash:   bytes.Repeat([]byte{0xcd}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
		GlobalPublicKey:  round2GlobalPubKey,
		PublicCoeffs:     round2PublicCoeffs,
	}
	cluster.MockQC.SetLatestActiveNetwork(round2Network)
	cluster.MockQC.SetRegistrationsByRound(round2, cluster.MockQC.GetCurrentRegistrations())

	round3Network := &pb.DKGNetwork{
		Round:            round3,
		StartBlockHeight: 300,
		StartBlockHash:   bytes.Repeat([]byte{0xef}, 32),
		Total:            uint32(len(cluster.Servers)),
		Threshold:        cluster.Threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
		IsResharing:      true,
	}
	cluster.MockQC.SetNetworkByRound(round3, round3Network)
	cluster.MockQC.SetNetwork(round3Network)

	round3KeyResps := make([]*pb.GenerateAndSealKeyResponse, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round3,
			Address:        cluster.Addresses[i],
		})
		require.NoError(t, err, "GenerateAndSealKey round 3 failed for node %d", i)
		round3KeyResps[i] = resp
	}

	round3Regs := make([]*pb.DKGRegistration, len(cluster.Servers))
	for i, resp := range round3KeyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		round3Regs[i] = &pb.DKGRegistration{
			Round:         round3,
			ValidatorAddr: cluster.Addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	cluster.MockQC.SetRegistrations(round3Regs)
	cluster.MockQC.SetRegistrationsByRound(round3, round3Regs)

	for _, srv := range cluster.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}

	n := len(cluster.Servers)
	dealResps := make([]*pb.GenerateDealsResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round3,
			IsResharing:    true,
		})
		require.NoError(t, err, "GenerateDeals round 3 failed for node %d", i)
		dealResps[i] = resp
	}

	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dr := range dealResps {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	processedResps := make([][]*pb.Response, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round3,
			IsResharing:    true,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals round 3 failed for node %d", i)
		processedResps[i] = resp.GetResponses()
	}

	var allResps []*pb.Response
	for _, resps := range processedResps {
		allResps = append(allResps, resps...)
	}

	for _, srv := range cluster.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round3,
			IsResharing:    true,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses round 3 failed")
	}

	finalizeResps := make([]*pb.FinalizeDKGResponse, n)
	for i, srv := range cluster.Servers {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          round3,
			IsResharing:    true,
		})
		require.NoError(t, err, "FinalizeDKG round 3 failed for node %d", i)
		finalizeResps[i] = resp
	}

	cluster.FinalizeResps = finalizeResps
	cluster.Round = round3

	for i, srv := range cluster.Servers {
		srv.PIDCache.Set(round3, uint32(i+1))
	}

	cluster.MockQC.SetLatestActiveNetwork(round3Network)
}

// TestMultiRound_ThreeSequentialRounds verifies three sequential DKG rounds:
// R1 fresh DKG → R2 resharing → R3 resharing. Asserts that global_pub_key is
// preserved through all three rounds and that the R3 committee can decrypt a
// ciphertext originally encrypted using the R1 public key.
func TestMultiRound_ThreeSequentialRounds(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	// Round 1: fresh DKG
	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round1GlobalPubKey)

	// Encrypt with R1 public key before any resharing
	tdh2PubKey, err := buildTDH2PubKey(round1GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("multi-round three sequential resharing test")
	label := []byte("multi-round-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	// Round 2: resharing
	runResharingRound2(t, cluster)
	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round2GlobalPubKey)
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"global_pub_key must be preserved after R1→R2 resharing")

	// Round 3: resharing again
	runResharingRound3(t, cluster)
	round3GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round3GlobalPubKey)
	require.True(t, bytes.Equal(round1GlobalPubKey, round3GlobalPubKey),
		"global_pub_key must be preserved after R2→R3 resharing")

	// All R3 nodes must agree on global_pub_key
	for i := 1; i < len(cluster.Servers); i++ {
		require.True(t, bytes.Equal(round3GlobalPubKey, cluster.FinalizeResps[i].GetGlobalPubKey()),
			"node %d R3 global_pub_key mismatch", i)
	}

	// R3 committee can decrypt the R1 ciphertext
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, round3GlobalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, round3GlobalPubKey, label, requesterPriv)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(1): result1.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(1): result1.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err, "R3 committee must decrypt R1 ciphertext after two rounds of resharing")
	require.Equal(t, plaintext, decrypted)
}
