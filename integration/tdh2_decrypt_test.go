package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
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

	return &partialDecryptResult{
		Partial:  &mpc.TDH2PartialDecryption{Bytes: partialBytes},
		PubShare: resp.GetPubShare(),
	}
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
