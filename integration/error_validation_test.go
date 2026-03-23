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
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
		Label:           []byte("invalid-requester-test"),
		RequesterPubKey: []byte("not-a-valid-pubkey"), // malformed
	})
	require.Error(t, err, "invalid requester_pub_key should be rejected")
	require.Equal(t, codes.Internal, status.Code(err), "expected Internal status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_DecryptRequestNotExist verifies that PartialDecryptTDH2 rejects
// a request when the decrypt request does not exist on the canonical chain.
func TestErrorValidation_DecryptRequestNotExist(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	label := []byte("no-request-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("no-request test"), label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Override mock to return false (decrypt request not found on-chain)
	cluster.MockQC.SetHasDecryptRequestResult(false)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 should fail when decrypt request does not exist")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
	require.Contains(t, err.Error(), "decrypt request does not exist")
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
		Label:           []byte("round-mismatch-test"),
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "round mismatch should be rejected by PartialDecryptTDH2")
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "expected FailedPrecondition status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
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
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// ---------------------------------------------------------------------------
// G1: PartialDecryptTDH2 when PID is not in cache
// ---------------------------------------------------------------------------

// TestErrorValidation_PartialDecrypt_PIDNotCached verifies that PartialDecryptTDH2
// returns an error when the node's own PID is absent from PIDCache.
// This happens when a node restarts and never replayed GenerateDeals, so it
// has sealed DKG state on disk but does not know its participant index.
func TestErrorValidation_PartialDecrypt_PIDNotCached(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	t.Logf("[G1] DKG complete: round=%d global_pub_key len=%d prefix=%x",
		cluster.Round, len(globalPubKey), globalPubKey[:4])

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("pid-not-cached test")
	label := []byte("g1-pid-test-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)
	t.Logf("[G1] Encrypted plaintext=%q ciphertext_len=%d label=%q", plaintext, len(ct.Bytes), label)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)
	t.Logf("[G1] Requester secp256k1 pub key len=%d", len(requesterPubBytes))

	// Rebuild a server using the same tempDir but with PIDCache deliberately empty.
	// Unlike rebuildServer(), we intentionally skip PIDCache.Set() to simulate a
	// node that restarted and never called GenerateDeals (so its PID is unknown).
	dir := cluster.TempDirs[0]
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cfg := config.DefaultConfig()
	cfg.SetHomeDir(dir)

	noPIDServer := &service.DKGServer{
		Cfg:                cfg,
		QueryClient:        cluster.MockQC,
		Suite:              suite,
		RoundCtxCache:      store.NewRoundContextCache(),
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
		DistKeyShareCache:  store.NewDistKeyShareCache(),
		DKGStore:           store.NewDKGStore(cfg.GetKeysDir(), cfg.GetDKGStateDir(), suite),
		PIDCache:           store.NewPIDCache(), // intentionally empty — PID.Set() never called
	}
	t.Logf("[G1] Built fresh DKGServer for node 0 with empty PIDCache (no PID set for round=%d)", cluster.Round)

	ctx := context.Background()
	_, err = noPIDServer.PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	t.Logf("[G1] PartialDecryptTDH2 (PID not cached) returned err=%v", err)
	require.Error(t, err, "PartialDecryptTDH2 must fail when PID is not in cache")
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "expected FailedPrecondition status code")
}

// ---------------------------------------------------------------------------
// G3: FinalizeDKG input validation
// ---------------------------------------------------------------------------

// TestErrorValidation_FinalizeDKGZeroRound verifies that FinalizeDKG rejects round=0.
func TestErrorValidation_FinalizeDKGZeroRound(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	t.Logf("[G3] Testing FinalizeDKG with round=0 (invalid)")

	ctx := context.Background()
	_, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          0, // invalid
	})
	t.Logf("[G3] FinalizeDKG(round=0) returned err=%v", err)
	require.Error(t, err, "FinalizeDKG with round=0 should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_FinalizeDKGEmptyCodeCommitment verifies that FinalizeDKG
// rejects an empty code_commitment field.
func TestErrorValidation_FinalizeDKGEmptyCodeCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	t.Logf("[G3] Testing FinalizeDKG with empty code_commitment")

	ctx := context.Background()
	_, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: []byte{}, // empty
		Round:          cluster.Round,
	})
	t.Logf("[G3] FinalizeDKG(empty code_commitment) returned err=%v", err)
	require.Error(t, err, "FinalizeDKG with empty code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// ---------------------------------------------------------------------------
// G4: ProcessResponses with empty responses list
// ---------------------------------------------------------------------------

// TestErrorValidation_ProcessResponsesEmptyResponses verifies that ProcessResponses
// rejects a nil/empty responses list.
func TestErrorValidation_ProcessResponsesEmptyResponses(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	t.Logf("[G4] Completed GenerateAllKeys + GenerateAllDeals")
	t.Logf("[G4] Testing ProcessResponses with nil responses (should be rejected)")

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Responses:      nil, // empty — no responses to process
	})
	t.Logf("[G4] ProcessResponses(nil responses) returned err=%v", err)
	require.Error(t, err, "ProcessResponses with empty responses should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// ---------------------------------------------------------------------------
// G5: PartialDecryptTDH2 with empty label / empty global_pub_key
// ---------------------------------------------------------------------------

// TestErrorValidation_EmptyLabel verifies that PartialDecryptTDH2 rejects an
// empty label field. The label is cryptographically bound to the ciphertext, so
// an empty label is treated as invalid input.
func TestErrorValidation_EmptyLabel(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	t.Logf("[G5-label] DKG complete: round=%d global_pub_key len=%d", cluster.Round, len(globalPubKey))

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	// Encrypt with a real label; then try to decrypt with empty label
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("empty-label test"), []byte("original-label"))
	require.NoError(t, err)
	t.Logf("[G5-label] Ciphertext encrypted with label=%q, len=%d", "original-label", len(ct.Bytes))

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           []byte{}, // empty label
		RequesterPubKey: requesterPubBytes,
	})
	t.Logf("[G5-label] PartialDecryptTDH2(empty label) returned err=%v", err)
	require.Error(t, err, "PartialDecryptTDH2 with empty label should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_EmptyGlobalPubKey verifies that PartialDecryptTDH2 rejects
// a nil/empty global_pub_key field.
func TestErrorValidation_EmptyGlobalPubKey(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	t.Logf("[G5-gpk] DKG complete: round=%d global_pub_key len=%d", cluster.Round, len(globalPubKey))

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	label := []byte("g5-gpk-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("empty global pub key test"), label)
	require.NoError(t, err)
	t.Logf("[G5-gpk] Ciphertext len=%d label=%q", len(ct.Bytes), label)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    nil, // missing global pub key
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	t.Logf("[G5-gpk] PartialDecryptTDH2(nil global_pub_key) returned err=%v", err)
	require.Error(t, err, "PartialDecryptTDH2 with nil global_pub_key should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// ---------------------------------------------------------------------------
// G6: WrongCodeCommitment for GenerateDeals, ProcessDeals, FinalizeDKG, PartialDecryptTDH2
// ---------------------------------------------------------------------------

// TestErrorValidation_WrongCodeCommitment_GenerateDeals verifies that GenerateDeals
// rejects a code_commitment that does not match the enclave MRENCLAVE.
func TestErrorValidation_WrongCodeCommitment_GenerateDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()

	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)
	t.Logf("[G6-deals] Testing GenerateDeals with wrong code_commitment=%x", wrongCommitment[:4])

	ctx := context.Background()
	_, err := cluster.Servers[0].GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: wrongCommitment,
		Round:          cluster.Round,
	})
	t.Logf("[G6-deals] GenerateDeals(wrong code_commitment) returned err=%v", err)
	require.Error(t, err, "GenerateDeals with wrong code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_WrongCodeCommitment_ProcessDeals verifies that ProcessDeals
// rejects a code_commitment that does not match the enclave MRENCLAVE.
func TestErrorValidation_WrongCodeCommitment_ProcessDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	// Collect deals for node 0
	n := len(cluster.Servers)
	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dr := range cluster.DealResponses {
		for _, deal := range dr.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}
	t.Logf("[G6-processdeals] Collected %d deals for node 0", len(dealsByRecipient[0]))

	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)
	t.Logf("[G6-processdeals] Testing ProcessDeals with wrong code_commitment=%x", wrongCommitment[:4])

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessDeals(ctx, &pb.ProcessDealsRequest{
		CodeCommitment: wrongCommitment,
		Round:          cluster.Round,
		Deals:          dealsByRecipient[0],
	})
	t.Logf("[G6-processdeals] ProcessDeals(wrong code_commitment) returned err=%v", err)
	require.Error(t, err, "ProcessDeals with wrong code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_WrongCodeCommitment_ProcessResponses verifies that
// ProcessResponses rejects a code_commitment that does not match the enclave
// MRENCLAVE. Covers the G6 gap for ProcessResponses.
func TestErrorValidation_WrongCodeCommitment_ProcessResponses(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()

	// Flatten all responses
	var allResps []*pb.Response
	for _, resps := range cluster.ProcessedResps {
		allResps = append(allResps, resps...)
	}
	require.NotEmpty(t, allResps, "should have responses from ProcessAllDeals")
	t.Logf("[G6-responses] Collected %d responses after ProcessAllDeals", len(allResps))

	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)
	t.Logf("[G6-responses] Testing ProcessResponses with wrong code_commitment=%x", wrongCommitment[:4])

	ctx := context.Background()
	_, err := cluster.Servers[0].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
		CodeCommitment: wrongCommitment,
		Round:          cluster.Round,
		Responses:      allResps,
	})
	t.Logf("[G6-responses] ProcessResponses(wrong code_commitment) returned err=%v", err)
	require.Error(t, err, "ProcessResponses with wrong code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_WrongCodeCommitment_FinalizeDKG verifies that FinalizeDKG
// rejects a code_commitment that does not match the enclave MRENCLAVE.
func TestErrorValidation_WrongCodeCommitment_FinalizeDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)
	t.Logf("[G6-finalize] Testing FinalizeDKG with wrong code_commitment=%x", wrongCommitment[:4])

	ctx := context.Background()
	_, err := cluster.Servers[0].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
		CodeCommitment: wrongCommitment,
		Round:          cluster.Round,
	})
	t.Logf("[G6-finalize] FinalizeDKG(wrong code_commitment) returned err=%v", err)
	require.Error(t, err, "FinalizeDKG with wrong code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// TestErrorValidation_WrongCodeCommitment_PartialDecryptTDH2 verifies that
// PartialDecryptTDH2 rejects a code_commitment that does not match the enclave MRENCLAVE.
func TestErrorValidation_WrongCodeCommitment_PartialDecryptTDH2(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	t.Logf("[G6-tdh2] DKG complete: round=%d global_pub_key len=%d", cluster.Round, len(globalPubKey))

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	label := []byte("g6-tdh2-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("wrong commitment partial decrypt test"), label)
	require.NoError(t, err)
	t.Logf("[G6-tdh2] Encrypted ciphertext len=%d label=%q", len(ct.Bytes), label)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	wrongCommitment := bytes.Repeat([]byte{0xDE}, 32)
	t.Logf("[G6-tdh2] Testing PartialDecryptTDH2 with wrong code_commitment=%x", wrongCommitment[:4])

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  wrongCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	t.Logf("[G6-tdh2] PartialDecryptTDH2(wrong code_commitment) returned err=%v", err)
	require.Error(t, err, "PartialDecryptTDH2 with wrong code_commitment should be rejected")
	require.Equal(t, codes.InvalidArgument, status.Code(err), "expected InvalidArgument status code")
}

// ---------------------------------------------------------------------------
// K-TDH2-01: Truncated / malformed ciphertext
// ---------------------------------------------------------------------------

// TestErrorValidation_TruncatedCiphertext verifies that PartialDecryptTDH2
// returns an error when given a truncated ciphertext (non-empty but too short
// to be a valid TDH2 ciphertext). The cb-mpc library should reject it.
//
// Covers K-TDH2-01 from the code review.
func TestErrorValidation_TruncatedCiphertext(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	// 16 bytes: non-empty but far too short for a valid TDH2 ciphertext
	truncatedCT := bytes.Repeat([]byte{0xCA}, 16)
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      truncatedCT,
		GlobalPubKey:    globalPubKey,
		Label:           []byte("truncated-ct-test"),
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 must reject truncated ciphertext")
	require.Equal(t, codes.Internal, status.Code(err), "expected Internal status code")
}

// ---------------------------------------------------------------------------
// K-TDH2-02: Mismatched label — partial decrypt may succeed but combine fails
// ---------------------------------------------------------------------------

// TestErrorValidation_MismatchedLabel verifies that using a different label
// during partial decryption than was used during encryption causes TDH2Combine
// to fail. The label is cryptographically bound to the ciphertext; a mismatch
// produces invalid partials that cannot be combined.
//
// Covers K-TDH2-02 from the code review.
func TestErrorValidation_MismatchedLabel(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("mismatched label test")
	encryptLabel := []byte("correct-label")
	wrongLabel := []byte("wrong-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, encryptLabel)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()

	// Collect partials using the WRONG label
	results := make([]*partialDecryptResult, 2)
	for i := range 2 {
		resp, partialErr := cluster.Servers[i].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
			CodeCommitment:  cluster.CodeCommitment,
			Round:           cluster.Round,
			Ciphertext:      ct.Bytes,
			GlobalPubKey:    globalPubKey,
			Label:           wrongLabel, // mismatch
			RequesterPubKey: requesterPubBytes,
		})
		// Partial decrypt itself may succeed (label is passed to cb-mpc, not validated at RPC level)
		if partialErr != nil {
			t.Logf("PartialDecryptTDH2 with wrong label returned error for node %d: %v (acceptable)", i, partialErr)
			return // If the service rejects it outright, the test still passes
		}

		partialBytes, decErr := decryptPartialFromRequester(requesterPriv, resp.GetEphemeralPubKey(), resp.GetEncryptedPartialDecryption())
		require.NoError(t, decErr)
		results[i] = &partialDecryptResult{
			Partial:  &mpc.TDH2PartialDecryption{Bytes: partialBytes},
			PubShare: resp.GetPubShare(),
		}
	}

	// Combine should fail because partials were computed with the wrong label
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): results[0].PubShare,
		NodeName(1): results[1].PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): results[0].Partial,
		NodeName(1): results[1].Partial,
	}

	decrypted, combineErr := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, wrongLabel, pdMap)
	// Primary assertion: TDH2Combine should fail because the label is cryptographically
	// bound to the ciphertext. A mismatched label produces invalid partials.
	if combineErr != nil {
		t.Logf("TDH2Combine correctly failed with mismatched label: %v", combineErr)
		return
	}
	// Unexpected: combine succeeded despite label mismatch. This would be a security
	// concern. At minimum, the plaintext must NOT match the original.
	t.Log("WARNING: TDH2Combine succeeded with mismatched label — this is unexpected")
	require.NotEqual(t, plaintext, decrypted,
		"decryption with mismatched label must not produce the original plaintext")
}

// ---------------------------------------------------------------------------
// K-TDH2-03: Invalid PID (0 or out of range)
// ---------------------------------------------------------------------------

// TestErrorValidation_InvalidPID_Zero verifies that PartialDecryptTDH2 fails
// when PIDCache contains PID=0 for the requested round. PID=0 is invalid
// because participant indices are 1-based in the kyber DKG protocol.
//
// Covers K-TDH2-03 from the code review.
func TestErrorValidation_InvalidPID_Zero(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("pid-zero test"), []byte("pid0-label"))
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Inject PID=0 into node 0's cache
	cluster.Servers[0].PIDCache.Set(cluster.Round, 0)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           []byte("pid0-label"),
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 must fail when PID=0 (invalid 1-based index)")
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "expected FailedPrecondition status code")
}

// TestErrorValidation_InvalidPID_OutOfRange verifies that PartialDecryptTDH2
// fails when PIDCache contains a PID larger than the number of participants.
//
// Covers K-TDH2-03 from the code review.
func TestErrorValidation_InvalidPID_OutOfRange(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("pid-oor test"), []byte("pid-oor-label"))
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Inject PID=999 (way beyond 3 participants) into node 0's cache
	cluster.Servers[0].PIDCache.Set(cluster.Round, 999)

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           []byte("pid-oor-label"),
		RequesterPubKey: requesterPubBytes,
	})
	require.Error(t, err, "PartialDecryptTDH2 must fail when PID exceeds number of participants")
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "expected FailedPrecondition status code")
}

// ---------------------------------------------------------------------------
// Cross-round share injection: wrong DistKeyShare in cache
// ---------------------------------------------------------------------------

// TestErrorValidation_PartialDecrypt_CrossRoundShareInjection verifies that
// injecting a DistKeyShare from a previous round into the cache for the current
// round causes TDH2Combine to fail or produce incorrect plaintext. This documents
// the impact of cache pollution: a stale share produces invalid partials that are
// incompatible with honest nodes' partials from the correct round.
//
// Steps:
//  1. Run Round 1 DKG (3 nodes, threshold=2)
//  2. Run Round 2 resharing (all 3 nodes participate in both committees)
//  3. Save Round 1's DistKeyShare for node 0
//  4. Overwrite node 0's Round 2 DistKeyShareCache entry with the Round 1 share
//  5. Encrypt a plaintext using Round 2's global pub key
//  6. Collect partial decrypts from node 0 (wrong share) and node 1 (correct share)
//  7. Assert: TDH2Combine fails or decrypted plaintext does not match original
func TestErrorValidation_PartialDecrypt_CrossRoundShareInjection(t *testing.T) {
	// Step 1: Run Round 1 DKG
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	round1GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round1GlobalPubKey)
	t.Logf("[CrossRound] Round 1 DKG complete: global_pub_key len=%d prefix=%x",
		len(round1GlobalPubKey), round1GlobalPubKey[:4])

	// Step 2: Save Round 1's DistKeyShare for node 0 (before resharing overwrites it)
	round1Share, ok := cluster.Servers[0].DistKeyShareCache.Get(round1)
	require.True(t, ok, "node 0 must have a DistKeyShare cached for round 1")
	// Deep copy the share to avoid aliasing issues after resharing
	round1ShareCopy := &dkg.DistKeyShare{
		Commits: round1Share.Commits,
		Share:   round1Share.Share,
	}
	t.Logf("[CrossRound] Saved Round 1 DistKeyShare for node 0")

	// Step 3: Run Round 2 resharing
	runResharingRound2(t, cluster)

	round2GlobalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	require.NotEmpty(t, round2GlobalPubKey)
	t.Logf("[CrossRound] Round 2 resharing complete: global_pub_key len=%d prefix=%x",
		len(round2GlobalPubKey), round2GlobalPubKey[:4])

	// Verify global pub key preserved (sanity check)
	require.True(t, bytes.Equal(round1GlobalPubKey, round2GlobalPubKey),
		"global_pub_key must be preserved after resharing")

	// Step 4: Inject Round 1's DistKeyShare into node 0's cache for Round 2
	// This simulates cache pollution: node 0 has a stale share from the wrong round
	cluster.Servers[0].DistKeyShareCache.Set(round2, round1ShareCopy)
	t.Logf("[CrossRound] Injected Round 1 DistKeyShare into node 0's cache for Round 2")

	// Step 5: Encrypt a plaintext using Round 2's global pub key
	tdh2PubKey, err := buildTDH2PubKey(round2GlobalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("cross-round share injection test")
	label := []byte("cross-round-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)
	t.Logf("[CrossRound] Encrypted plaintext=%q ciphertext_len=%d", plaintext, len(ct.Bytes))

	// Step 6: Collect partial decrypts
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Node 0: has wrong (Round 1) share in cache — partial will be computed with stale key
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	t.Logf("[CrossRound] Node 0 (wrong share) partial collected: partial_len=%d pub_share_len=%d",
		len(result0.Partial.Bytes), len(result0.PubShare))

	// Node 1: has correct Round 2 share — honest partial
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, round2GlobalPubKey, label, requesterPriv)
	t.Logf("[CrossRound] Node 1 (correct share) partial collected: partial_len=%d pub_share_len=%d",
		len(result1.Partial.Bytes), len(result1.PubShare))

	// Step 7: Try to combine the partials (1 wrong + 1 correct)
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

	decrypted, combineErr := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	if combineErr != nil {
		t.Logf("[CrossRound] TDH2Combine correctly failed with cross-round share: %v", combineErr)
		return
	}

	// If combine didn't error, the decrypted plaintext must NOT match the original.
	// Matching would mean the stale share was silently accepted — a security concern.
	t.Logf("[CrossRound] WARNING: TDH2Combine succeeded despite cross-round share injection")
	require.NotEqual(t, plaintext, decrypted,
		"decryption with cross-round injected share must not produce the original plaintext")
}
