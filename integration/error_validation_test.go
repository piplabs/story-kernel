package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestErrorValidation_ZeroRound verifies that round=0 is rejected by GenerateAndSealKey.
func TestErrorValidation_ZeroRound(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          0, // invalid
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "round=0 should be rejected")
}

// TestErrorValidation_EmptyCodeCommitment verifies that an empty code_commitment is rejected.
func TestErrorValidation_EmptyCodeCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: []byte{}, // empty
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "empty code_commitment should be rejected")
}

// TestErrorValidation_WrongCodeCommitment verifies that a code_commitment that doesn't
// match the enclave MR_ENCLAVE is rejected.
func TestErrorValidation_WrongCodeCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32) // wrong 32-byte value

	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: wrongCommitment,
		Round:          cluster.Round,
		Address:        cluster.Addresses[0],
	})
	require.Error(t, err, "wrong code_commitment should be rejected")
}

// TestErrorValidation_EmptyAddress verifies that an empty address is rejected.
func TestErrorValidation_EmptyAddress(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Address:        "", // empty
	})
	require.Error(t, err, "empty address should be rejected")
}

// TestErrorValidation_EmptyCiphertext verifies that PartialDecryptTDH2 rejects empty ciphertext.
func TestErrorValidation_EmptyCiphertext(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      []byte{}, // empty
		GlobalPubKey:    globalPubKey,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "empty ciphertext should be rejected")
}

// TestErrorValidation_InvalidRequesterPubKey verifies that PartialDecryptTDH2 rejects
// a malformed requester_pub_key.
func TestErrorValidation_InvalidRequesterPubKey(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	ctx := context.Background()
	_, err := cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      bytes.Repeat([]byte{0xAB}, 64), // non-empty but invalid ct
		GlobalPubKey:    globalPubKey,
		RequesterPubKey: []byte("not-a-valid-pubkey"), // malformed
	})
	require.Error(t, err, "invalid requester_pub_key should be rejected")
}

// TestErrorValidation_MissingRequesterPubKey verifies that PartialDecryptTDH2 rejects
// a missing (nil/empty) requester_pub_key.
func TestErrorValidation_MissingRequesterPubKey(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	ctx := context.Background()
	_, err := cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      bytes.Repeat([]byte{0xAB}, 64),
		GlobalPubKey:    globalPubKey,
		RequesterPubKey: nil, // missing
	})
	require.Error(t, err, "missing requester_pub_key should be rejected")
}

// TestErrorValidation_RoundMismatchPartialDecrypt verifies that PartialDecryptTDH2 rejects
// a round that doesn't match the latest active DKG network.
func TestErrorValidation_RoundMismatchPartialDecrypt(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round + 99, // wrong round
		Ciphertext:      bytes.Repeat([]byte{0xAB}, 64),
		GlobalPubKey:    globalPubKey,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "round mismatch should be rejected by PartialDecryptTDH2")
}

// TestErrorValidation_GenerateDealsZeroRound verifies that GenerateDeals rejects round=0.
func TestErrorValidation_GenerateDealsZeroRound(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          0, // invalid
	})
	require.Error(t, err, "GenerateDeals with round=0 should be rejected")
}

// TestErrorValidation_ProcessDealsEmptyDeals verifies that ProcessDeals rejects empty deals list.
func TestErrorValidation_ProcessDealsEmptyDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Deals:          nil, // empty
	})
	require.Error(t, err, "ProcessDeals with empty deals should be rejected")
}

// TestErrorValidation_ProcessJustification_ZeroRound verifies that round=0 is rejected.
func TestErrorValidation_ProcessJustification_ZeroRound(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          0, // invalid
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
	})
	require.Error(t, err, "ProcessJustification with round=0 should be rejected")
}

// TestErrorValidation_ProcessJustification_EmptyCodeCommitment verifies that
// an empty code_commitment is rejected by ProcessJustification.
func TestErrorValidation_ProcessJustification_EmptyCodeCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: []byte{}, // empty
		Round:          1,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
	})
	require.Error(t, err, "ProcessJustification with empty code_commitment should be rejected")
}

// TestErrorValidation_ProcessJustification_EmptyJustifications verifies that
// an empty justifications list is rejected by ProcessJustification.
func TestErrorValidation_ProcessJustification_EmptyJustifications(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          1,
		Justifications: nil, // empty
	})
	require.Error(t, err, "ProcessJustification with empty justifications should be rejected")
}

// TestErrorValidation_ProcessJustification_WrongCodeCommitment verifies that a
// code_commitment not matching the enclave MRENCLAVE is rejected.
func TestErrorValidation_ProcessJustification_WrongCodeCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)

	_, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: wrongCommitment,
		Round:          1,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
	})
	require.Error(t, err, "ProcessJustification with wrong code_commitment should be rejected")
}
