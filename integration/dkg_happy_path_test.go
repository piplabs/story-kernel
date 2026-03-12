package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestDKGHappyPath_3Nodes runs the complete 3-node DKG flow and validates all results.
func TestDKGHappyPath_3Nodes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	t.Logf("[setup] nodes=%d threshold=%d codeCommitment=%x round=%d",
		3, 2, cluster.CodeCommitment, cluster.Round)

	cluster.RunFullDKG()

	t.Log("[phase] RunFullDKG completed")

	// Validate key responses
	for i, kr := range cluster.KeyResponses {
		require.NotEmpty(t, kr.GetDkgPubKey(), "node %d: empty DkgPubKey", i)
		require.NotEmpty(t, kr.GetCommPubKey(), "node %d: empty CommPubKey", i)
		require.NotEmpty(t, kr.GetEnclaveReport(), "node %d: empty EnclaveReport", i)
		t.Logf("[key] node %d: dkg_pub_key=%x comm_pub_key=%x enclave_report_len=%d",
			i, kr.GetDkgPubKey(), kr.GetCommPubKey(), len(kr.GetEnclaveReport()))
	}

	// Validate deals: each node should generate n-1 deals (one per peer)
	expectedDeals := len(cluster.Servers) - 1
	for i, dr := range cluster.DealResponses {
		require.Len(t, dr.GetDeals(), expectedDeals, "node %d: expected %d deals", i, expectedDeals)
		t.Logf("[deal] node %d: deals=%d (expected %d)", i, len(dr.GetDeals()), expectedDeals)
		for j, d := range dr.GetDeals() {
			enc := d.GetDeal()
			var dhKey, nonce, sig, cipher string
			if enc != nil {
				dhKey = fmt.Sprintf("%x", enc.GetDhKey())
				nonce = fmt.Sprintf("%x", enc.GetNonce())
				sig = fmt.Sprintf("%x", enc.GetSignature())
				cipher = fmt.Sprintf("len=%d", len(enc.GetCipher()))
			}
			t.Logf("[deal] node %d deal[%d]: from=%d to=%d signature=%x dh_key=%s nonce=%s encrypted_sig=%s cipher=%s",
				i, j, d.GetIndex(), d.GetRecipientIndex(), d.GetSignature(), dhKey, nonce, sig, cipher)
		}
	}

	// Validate finalize responses
	require.Len(t, cluster.FinalizeResps, 3)

	// All nodes must agree on the global public key
	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	t.Logf("[finalize] global_pub_key=%x (len=%d)", globalPubKey, len(globalPubKey))
	require.NotEmpty(t, globalPubKey, "global pub key should not be empty")
	for i := 1; i < 3; i++ {
		require.True(t,
			bytes.Equal(globalPubKey, cluster.FinalizeResps[i].GetGlobalPubKey()),
			"node %d global_pub_key mismatch", i)
	}

	// All nodes must agree on public_coeffs
	coeffs0 := cluster.FinalizeResps[0].GetPublicCoeffs()
	require.NotEmpty(t, coeffs0)
	t.Logf("[finalize] public_coeffs count=%d", len(coeffs0))
	for j, c := range coeffs0 {
		t.Logf("[finalize] public_coeff[%d]=%x", j, c)
	}
	for i := 1; i < 3; i++ {
		coeffsI := cluster.FinalizeResps[i].GetPublicCoeffs()
		require.Len(t, coeffsI, len(coeffs0))
		for j := range coeffs0 {
			require.True(t,
				bytes.Equal(coeffs0[j], coeffsI[j]),
				"node %d public_coeff[%d] mismatch", i, j)
		}
	}

	// pub_key_share must differ between nodes
	shares := make([][]byte, 3)
	for i, fr := range cluster.FinalizeResps {
		shares[i] = fr.GetPubKeyShare()
		require.NotEmpty(t, shares[i], "node %d: empty pub_key_share", i)
		t.Logf("[finalize] node %d: pub_key_share=%x participants_root=%x signature=%x",
			i, fr.GetPubKeyShare(), fr.GetParticipantsRoot(), fr.GetSignature())
	}
	require.False(t, bytes.Equal(shares[0], shares[1]), "node 0 and 1 shares should differ")
	require.False(t, bytes.Equal(shares[1], shares[2]), "node 1 and 2 shares should differ")

	// Verify finalization signatures
	var codeCommitment [32]byte
	copy(codeCommitment[:], cluster.CodeCommitment)

	regs, err := cluster.MockQC.GetAllVerifiedDKGRegistrations(context.Background(), hex.EncodeToString(cluster.CodeCommitment), cluster.Round)
	require.NoError(t, err)
	t.Logf("[registry] loaded %d registrations", len(regs))

	for i, fr := range cluster.FinalizeResps {
		var participantsRoot [32]byte
		copy(participantsRoot[:], fr.GetParticipantsRoot())

		// CommPubKey in registration is 65 bytes (with 0x04 prefix)
		commPubKey := regs[i].GetCommPubKey()
		require.Len(t, commPubKey, 65)
		t.Logf("[verify] node %d: comm_pub_key=%x participants_root=%x", i, commPubKey, participantsRoot)

		ok := verifyFinalizationSignature(
			commPubKey,
			cluster.Round,
			codeCommitment,
			participantsRoot,
			fr.GetGlobalPubKey(),
			fr.GetPublicCoeffs(),
			fr.GetPubKeyShare(),
			fr.GetSignature(),
		)
		t.Logf("[verify] node %d: signature_ok=%v", i, ok)
		require.True(t, ok, "node %d: finalization signature verification failed", i)
	}
}

// TestDKGHappyPath_Idempotent verifies that GenerateAndSealKey is idempotent.
func TestDKGHappyPath_Idempotent(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()

	// First call
	resp1, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.NoError(t, err)

	// Second call — should load from seal and return the same keys
	resp2, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.NoError(t, err)

	require.True(t, bytes.Equal(resp1.GetDkgPubKey(), resp2.GetDkgPubKey()),
		"second call should return the same DKG pub key")
	require.True(t, bytes.Equal(resp1.GetCommPubKey(), resp2.GetCommPubKey()),
		"second call should return the same comm pub key")
}
