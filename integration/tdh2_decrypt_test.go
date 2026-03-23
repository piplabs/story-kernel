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

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// partialDecryptResult holds the outputs of a single PartialDecryptTDH2 call.
type partialDecryptResult struct {
	Partial  *mpc.TDH2PartialDecryption
	PubShare []byte
}

// collectPartialDecrypt calls PartialDecryptTDH2 on one node and decrypts the encrypted partial.
func collectPartialDecrypt(
	t *testing.T,
	cluster *DKGTestCluster,
	nodeIdx int,
	ciphertext []byte,
	globalPubKey []byte,
	label []byte,
	requesterPriv *ecdsa.PrivateKey,
) *partialDecryptResult {
	t.Helper()
	result, err := tryCollectPartialDecrypt(cluster, nodeIdx, ciphertext, globalPubKey, label, requesterPriv)
	require.NoError(t, err, "collectPartialDecrypt failed for node %d", nodeIdx)
	return result
}

// tryCollectPartialDecrypt is the error-returning variant of collectPartialDecrypt,
// safe to call from goroutines (no require/t.FailNow).
func tryCollectPartialDecrypt(
	cluster *DKGTestCluster,
	nodeIdx int,
	ciphertext []byte,
	globalPubKey []byte,
	label []byte,
	requesterPriv *ecdsa.PrivateKey,
) (*partialDecryptResult, error) {
	ctx := context.Background()

	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	resp, err := cluster.Servers[nodeIdx].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ciphertext,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("PartialDecryptTDH2 failed for node %d: %w", nodeIdx, err)
	}

	partialBytes, err := decryptPartialFromRequester(requesterPriv, resp.GetEphemeralPubKey(), resp.GetEncryptedPartialDecryption())
	if err != nil {
		return nil, fmt.Errorf("decryptPartialFromRequester failed for node %d: %w", nodeIdx, err)
	}

	return &partialDecryptResult{
		Partial:  &mpc.TDH2PartialDecryption{Bytes: partialBytes},
		PubShare: resp.GetPubShare(),
	}, nil
}

// collectPartialDecryptRaw calls PartialDecryptTDH2 and returns the raw gRPC response
// (including Signature) along with the decrypted partial. Used by signature verification tests.
func collectPartialDecryptRaw(
	t *testing.T,
	cluster *DKGTestCluster,
	nodeIdx int,
	ciphertext []byte,
	globalPubKey []byte,
	label []byte,
	requesterPriv *ecdsa.PrivateKey,
) (*pb.PartialDecryptTDH2Response, *partialDecryptResult) {
	t.Helper()
	ctx := context.Background()

	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	resp, err := cluster.Servers[nodeIdx].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ciphertext,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.NoError(t, err, "PartialDecryptTDH2 failed for node %d", nodeIdx)

	partialBytes, err := decryptPartialFromRequester(requesterPriv, resp.GetEphemeralPubKey(), resp.GetEncryptedPartialDecryption())
	require.NoError(t, err, "decryptPartialFromRequester failed for node %d", nodeIdx)

	result := &partialDecryptResult{
		Partial:  &mpc.TDH2PartialDecryption{Bytes: partialBytes},
		PubShare: resp.GetPubShare(),
	}

	return resp, result
}

// runTDH2Setup runs a full DKG and returns a ready cluster.
func runTDH2Setup(t *testing.T) *DKGTestCluster {
	t.Helper()
	cluster := NewDKGTestCluster(t, 3, 2)
	cluster.RunFullDKG()
	return cluster
}

// buildTDH2PubKey wraps the raw global pub key bytes for TDH2.
// TDH2PublicKeyFromPoint expects a point encoded as:
//   - 0x04: uncompressed EC point prefix
//   - 0x3f: cb-mpc curve type tag identifying Ed25519 (63 decimal)
//   - globalPubKey: 32-byte Ed25519 point from FinalizeDKGResponse
func buildTDH2PubKey(globalPubKey []byte) (*mpc.TDH2PublicKey, error) {
	tdhPointBytes := append([]byte{0x04, 0x3f}, globalPubKey...)
	return mpc.TDH2PublicKeyFromPoint(tdhPointBytes)
}

// TestTDH2_PartialDecryptAndCombine tests TDH2 encrypt → 3 partials → combine with 2.
func TestTDH2_PartialDecryptAndCombine(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("hello TDH2 threshold decryption")
	label := []byte("test-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partials from all 3 nodes
	results := make([]*partialDecryptResult, 3)
	for i := range 3 {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, globalPubKey, label, requesterPriv)
	}

	// Build access structure for 2-of-3
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Combine with nodes 0 and 1
	pubShares := map[string][]byte{
		NodeName(0): results[0].PubShare,
		NodeName(1): results[1].PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): results[0].Partial,
		NodeName(1): results[1].Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestTDH2_ThresholdNotMet verifies that only 1 partial cannot decrypt (threshold=2).
func TestTDH2_ThresholdNotMet(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("secret message")
	label := []byte("test-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	result := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Only 1 partial — must fail
	pubShares := map[string][]byte{NodeName(0): result.PubShare}
	pdMap := map[string]*mpc.TDH2PartialDecryption{NodeName(0): result.Partial}

	_, err = mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.Error(t, err, "combining with 1 partial should fail when threshold is 2")
}

// TestTDH2_WrongLabel verifies that encrypting with label A and combining with label B
// causes TDH2Combine to fail or produce incorrect output. The label is authenticated
// during encryption and must match at combine time for decryption to succeed.
func TestTDH2_WrongLabel(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("wrong label test")
	labelA := []byte("label-A-encrypt")
	labelB := []byte("label-B-combine")

	// Encrypt with label A
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, labelA)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partials using the correct label A (PartialDecryptTDH2 needs the matching label)
	results := make([]*partialDecryptResult, 3)
	for i := range 3 {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, globalPubKey, labelA, requesterPriv)
	}

	// Build access structure for 2-of-3
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Combine with wrong label B — should fail or produce wrong output
	pubShares := map[string][]byte{
		NodeName(0): results[0].PubShare,
		NodeName(1): results[1].PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): results[0].Partial,
		NodeName(1): results[1].Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, labelB, pdMap)
	if err != nil {
		// TDH2Combine returned an error — label mismatch detected, test passes
		t.Logf("TDH2Combine correctly failed with wrong label: %v", err)
	} else {
		// If no error, the decrypted output must differ from the original plaintext
		require.NotEqual(t, plaintext, decrypted,
			"TDH2Combine with wrong label must not produce correct plaintext")
		t.Logf("TDH2Combine produced incorrect output with wrong label (len=%d)", len(decrypted))
	}
}

// TestTDH2_WrongGlobalPubKey verifies that calling PartialDecryptTDH2 with a
// globalPubKey different from the one used during encryption causes an error.
// The globalPubKey is used to build the TDH2 public key for partial decryption;
// a mismatch means the partial will fail or produce unusable output.
func TestTDH2_WrongGlobalPubKey(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("wrong pub key test")
	label := []byte("wrong-pubkey-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Build a wrong globalPubKey — use 0xFF bytes of the same length
	wrongGlobalPubKey := make([]byte, len(globalPubKey))
	for i := range wrongGlobalPubKey {
		wrongGlobalPubKey[i] = 0xFF
	}

	ctx := context.Background()
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    wrongGlobalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	// PartialDecryptTDH2 calls buildTDH2PublicKey with the wrong key bytes.
	// This should fail because 0xFF...FF is not a valid Ed25519 point.
	require.Error(t, err, "PartialDecryptTDH2 should fail with an invalid globalPubKey")
}

// TestTDH2_AllCombinations verifies all C(3,2)=3 combinations of 2-of-3 can decrypt.
func TestTDH2_AllCombinations(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("all combinations test")
	label := []byte("combo-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect all 3 partials
	results := make([]*partialDecryptResult, 3)
	for i := range 3 {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, globalPubKey, label, requesterPriv)
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	combinations := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, combo := range combinations {
		a, b := combo[0], combo[1]
		t.Run(NodeName(a)+"+"+NodeName(b), func(t *testing.T) {
			pubShares := map[string][]byte{
				NodeName(a): results[a].PubShare,
				NodeName(b): results[b].PubShare,
			}
			pdMap := map[string]*mpc.TDH2PartialDecryption{
				NodeName(a): results[a].Partial,
				NodeName(b): results[b].Partial,
			}

			decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
			require.NoError(t, err, "combine failed for nodes %d+%d", a, b)
			require.Equal(t, plaintext, decrypted, "decrypted mismatch for nodes %d+%d", a, b)
		})
	}
}

// --- Signature verification tests (PR #18 review) ---

// TestTDH2_PartialDecryptSignatureValid verifies that the signature on a PartialDecryptTDH2
// response is a valid ECDSA signature and the recovered signer matches the node's CommPubKey.
func TestTDH2_PartialDecryptSignatureValid(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("signature validation test")
	label := []byte("sig-valid-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	regs := cluster.MockQC.GetCurrentRegistrations()
	for i := range cluster.Servers {
		resp, _ := collectPartialDecryptRaw(t, cluster, i, ct.Bytes, globalPubKey, label, requesterPriv)
		commPubKey := regs[i].GetCommPubKey()
		ok := verifyPartialDecryptSignature(t, resp, cluster.Round, ct.Bytes, commPubKey)
		require.True(t, ok, "node %d: signature verification failed — recovered signer does not match CommPubKey", i)
		t.Logf("node %d: partial decrypt signature verified successfully", i)
	}
}

// TestTDH2_SignatureBindsCiphertext verifies that different ciphertexts produce different
// signatures, proving the signature is bound to the specific ciphertext being decrypted.
func TestTDH2_SignatureBindsCiphertext(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	label := []byte("sig-binds-ct-label")

	ct1, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("plaintext one"), label)
	require.NoError(t, err)
	ct2, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("plaintext two"), label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	resp1, _ := collectPartialDecryptRaw(t, cluster, 0, ct1.Bytes, globalPubKey, label, requesterPriv)
	resp2, _ := collectPartialDecryptRaw(t, cluster, 0, ct2.Bytes, globalPubKey, label, requesterPriv)

	// The encrypted partials differ (different ciphertext → different partial decryption),
	// so the signatures must also differ since encryptedPartial is part of the signed data.
	require.False(t, bytes.Equal(resp1.GetSignature(), resp2.GetSignature()),
		"signatures for different ciphertexts must differ")
}

// TestTDH2_SignatureNonEmpty verifies basic signature field properties:
// non-empty, exactly 65 bytes (ECDSA r+s+v), and not all zeros.
func TestTDH2_SignatureNonEmpty(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("non-empty sig test"), []byte("label"))
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	resp, _ := collectPartialDecryptRaw(t, cluster, 0, ct.Bytes, globalPubKey, []byte("label"), requesterPriv)

	require.NotEmpty(t, resp.GetSignature(), "signature must not be empty")
	require.Len(t, resp.GetSignature(), 65, "ECDSA signature must be exactly 65 bytes (r+s+v)")
	require.False(t, bytes.Equal(resp.GetSignature(), make([]byte, 65)),
		"signature must not be all zeros")
}

// TestTDH2_SignatureConsistentAcrossNodes verifies that all nodes produce valid 65-byte
// signatures for the same ciphertext, but each signature is unique (different signing keys).
func TestTDH2_SignatureConsistentAcrossNodes(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("cross-node sig test"), []byte("label"))
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	sigs := make([][]byte, 3)
	for i := range cluster.Servers {
		resp, _ := collectPartialDecryptRaw(t, cluster, i, ct.Bytes, globalPubKey, []byte("label"), requesterPriv)
		require.Len(t, resp.GetSignature(), 65, "node %d: signature length mismatch", i)
		sigs[i] = resp.GetSignature()
	}

	// All signatures must be distinct (different secp256k1 keys per node)
	require.False(t, bytes.Equal(sigs[0], sigs[1]), "node 0 and 1 signatures should differ")
	require.False(t, bytes.Equal(sigs[1], sigs[2]), "node 1 and 2 signatures should differ")
	require.False(t, bytes.Equal(sigs[0], sigs[2]), "node 0 and 2 signatures should differ")
}

// TestTDH2_TamperedResponseFailsSignatureVerification verifies that tampering with any
// field of the PartialDecryptTDH2 response causes signature verification to fail.
func TestTDH2_TamperedResponseFailsSignatureVerification(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("tamper test"), []byte("tamper-label"))
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	resp, _ := collectPartialDecryptRaw(t, cluster, 0, ct.Bytes, globalPubKey, []byte("tamper-label"), requesterPriv)
	commPubKey := cluster.MockQC.GetCurrentRegistrations()[0].GetCommPubKey()

	// Sanity: original signature verifies
	ok := verifyPartialDecryptSignature(t, resp, cluster.Round, ct.Bytes, commPubKey)
	require.True(t, ok, "original signature should verify")

	// Tamper encryptedPartial
	t.Run("tamper_encryptedPartial", func(t *testing.T) {
		tampered := clonePartialDecryptResp(resp)
		tampered.EncryptedPartialDecryption[0] ^= 0xFF
		ok := verifyPartialDecryptSignature(t, tampered, cluster.Round, ct.Bytes, commPubKey)
		require.False(t, ok, "tampered encryptedPartial should fail verification")
	})

	// Tamper ephemeralPubKey
	t.Run("tamper_ephPubKey", func(t *testing.T) {
		tampered := clonePartialDecryptResp(resp)
		tampered.EphemeralPubKey[0] ^= 0xFF
		ok := verifyPartialDecryptSignature(t, tampered, cluster.Round, ct.Bytes, commPubKey)
		require.False(t, ok, "tampered ephPubKey should fail verification")
	})

	// Tamper pubShare
	t.Run("tamper_pubShare", func(t *testing.T) {
		tampered := clonePartialDecryptResp(resp)
		tampered.PubShare[0] ^= 0xFF
		ok := verifyPartialDecryptSignature(t, tampered, cluster.Round, ct.Bytes, commPubKey)
		require.False(t, ok, "tampered pubShare should fail verification")
	})
}

// TestTDH2_RepeatedDecryptSameCiphertext is a characterization test documenting that
// the kernel allows unlimited repeated decryption of the same ciphertext (no rate limiting).
// Chain-side prevents replay via UUID uniqueness + duplicate detection.
// See TODO at dkg_partial_decrypt.go:41-42 for the related kernel-side consideration.
func TestTDH2_RepeatedDecryptSameCiphertext(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("repeated decrypt test")
	label := []byte("repeat-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	ctx := context.Background()
	const repeatCount = 10
	encryptedPartials := make([][]byte, repeatCount)

	for i := range repeatCount {
		resp, err := cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
			CodeCommitment:  cluster.CodeCommitment,
			Round:           cluster.Round,
			Ciphertext:      ct.Bytes,
			GlobalPubKey:    globalPubKey,
			Label:           label,
			RequesterPubKey: requesterPubBytes,
		})
		require.NoError(t, err, "call %d: PartialDecryptTDH2 should succeed on repeated calls", i)
		encryptedPartials[i] = resp.GetEncryptedPartialDecryption()
	}

	t.Logf("Characterization: kernel allowed %d repeated decryptions of the same ciphertext without error (no rate limiting). "+
		"Chain-side prevents replay via UUID uniqueness + duplicate detection. See dkg_partial_decrypt.go:41-42.", repeatCount)

	// Verify all encrypted partials are unique (ephemeral key regenerated each time)
	for i := 0; i < repeatCount; i++ {
		for j := i + 1; j < repeatCount; j++ {
			require.False(t, bytes.Equal(encryptedPartials[i], encryptedPartials[j]),
				"encrypted partials from call %d and %d must differ (ephemeral key regenerated each time)", i, j)
		}
	}
}

// TestTDH2_DifferentRequestersSameCiphertext documents ECDH encryption isolation:
// different requesters get different encrypted partials for the same ciphertext,
// but the underlying TDH2 partial is functionally equivalent.
func TestTDH2_DifferentRequestersSameCiphertext(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("multi-requester test")
	label := []byte("multi-req-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	const numRequesters = 3
	requesterPrivs := make([]*ecdsa.PrivateKey, numRequesters)
	for i := range numRequesters {
		priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
		require.NoError(t, err)
		requesterPrivs[i] = priv
	}

	ctx := context.Background()
	encryptedPartials := make([][]byte, numRequesters)
	decryptedPartials := make([][]byte, numRequesters)
	pubSharesAll := make([][]byte, numRequesters)

	for i, priv := range requesterPrivs {
		requesterPubBytes := ecrypto.FromECDSAPub(&priv.PublicKey)

		resp, err := cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
			CodeCommitment:  cluster.CodeCommitment,
			Round:           cluster.Round,
			Ciphertext:      ct.Bytes,
			GlobalPubKey:    globalPubKey,
			Label:           label,
			RequesterPubKey: requesterPubBytes,
		})
		require.NoError(t, err, "requester %d: PartialDecryptTDH2 should succeed", i)
		encryptedPartials[i] = resp.GetEncryptedPartialDecryption()
		pubSharesAll[i] = resp.GetPubShare()

		partialBytes, err := decryptPartialFromRequester(priv, resp.GetEphemeralPubKey(), resp.GetEncryptedPartialDecryption())
		require.NoError(t, err, "requester %d: decryptPartialFromRequester should succeed", i)
		decryptedPartials[i] = partialBytes
	}

	// All encrypted partials must differ (ECDH with different requesters)
	for i := 0; i < numRequesters; i++ {
		for j := i + 1; j < numRequesters; j++ {
			require.False(t, bytes.Equal(encryptedPartials[i], encryptedPartials[j]),
				"encrypted partials for requester %d and %d must differ (different ECDH keys)", i, j)
		}
	}

	// TDH2 partial decryption includes per-call randomness, so decrypted partials
	// are NOT byte-equal. Instead, verify functional equivalence: each requester's
	// partial from node 0 can be combined with node 1's partial to recover plaintext.
	// Collect a partial from node 1 (same for all combiners)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPrivs[0])

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	for i, partial := range decryptedPartials {
		pubShares := map[string][]byte{
			NodeName(0): pubSharesAll[i],
			NodeName(1): result1.PubShare,
		}
		pdMap := map[string]*mpc.TDH2PartialDecryption{
			NodeName(0): &mpc.TDH2PartialDecryption{Bytes: partial},
			NodeName(1): result1.Partial,
		}
		decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
		require.NoError(t, err, "requester %d: TDH2Combine should succeed", i)
		require.Equal(t, plaintext, decrypted,
			"requester %d: decrypted plaintext must match original", i)
	}

	t.Logf("ECDH isolation verified: %d different requesters got %d unique encrypted partials, "+
		"each functionally equivalent (all combine to recover plaintext)", numRequesters, numRequesters)
}

// clonePartialDecryptResp creates a deep copy of a PartialDecryptTDH2Response.
func clonePartialDecryptResp(resp *pb.PartialDecryptTDH2Response) *pb.PartialDecryptTDH2Response {
	clone := &pb.PartialDecryptTDH2Response{
		EncryptedPartialDecryption: make([]byte, len(resp.EncryptedPartialDecryption)),
		EphemeralPubKey:            make([]byte, len(resp.EphemeralPubKey)),
		PubShare:                   make([]byte, len(resp.PubShare)),
		Signature:                  make([]byte, len(resp.Signature)),
	}
	copy(clone.EncryptedPartialDecryption, resp.EncryptedPartialDecryption)
	copy(clone.EphemeralPubKey, resp.EphemeralPubKey)
	copy(clone.PubShare, resp.PubShare)
	copy(clone.Signature, resp.Signature)
	return clone
}
