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
}
