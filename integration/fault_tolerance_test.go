package integration

import (
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

// TestFaultTolerance_OneNodeDown verifies that after DKG, only 2 of 3 nodes need to respond
// for threshold decryption (1 node "down" = simply not queried).
func TestFaultTolerance_OneNodeDown(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("one node down test")
	label := []byte("fault-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Only query nodes 0 and 1 (node 2 is "down")
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

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

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted, "decryption should succeed with 2-of-3 nodes")
}

// TestFaultTolerance_TwoNodesDown verifies that with only 1 of 3 nodes available,
// decryption fails (threshold=2). After a second node comes back, decryption succeeds.
func TestFaultTolerance_TwoNodesDown(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("two nodes down test")
	label := []byte("fault2-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Only 1 node available — must fail
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)

	pubShares1 := map[string][]byte{NodeName(0): result0.PubShare}
	pdMap1 := map[string]*mpc.TDH2PartialDecryption{NodeName(0): result0.Partial}

	_, err = mpc.TDH2Combine(as, tdh2PubKey, pubShares1, ct, label, pdMap1)
	require.Error(t, err, "combining with 1 partial (threshold=2) should fail")

	// Node 2 "comes back" — now 2 nodes available
	result2 := collectPartialDecrypt(t, cluster, 2, ct.Bytes, globalPubKey, label, requesterPriv)

	pubShares2 := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(2): result2.PubShare,
	}
	pdMap2 := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(2): result2.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares2, ct, label, pdMap2)
	require.NoError(t, err, "decryption should succeed after second node recovers")
	require.Equal(t, plaintext, decrypted)
}

// TestFaultTolerance_PartialDecryptNodeUnavailable verifies PartialDecryptTDH2 still works
// independently on each surviving node after one is not queried.
func TestFaultTolerance_PartialDecryptNodeUnavailable(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("node unavailable partial test")
	label := []byte("unavailable-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Nodes 0 and 2 respond; node 1 is "unavailable"
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result2 := collectPartialDecrypt(t, cluster, 2, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): result0.PubShare,
		NodeName(2): result2.PubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): result0.Partial,
		NodeName(2): result2.Partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestFaultTolerance_NodeRestartCanStillDecrypt verifies that a node that has been
// "restarted" (DistKeyShareCache cleared, forcing reload from sealed file) can still
// produce a valid partial decryption.
func TestFaultTolerance_NodeRestartCanStillDecrypt(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("restart recovery test")
	label := []byte("restart-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Simulate node 0 restart: clear its in-memory DistKeyShare cache
	// This forces PartialDecryptTDH2 to reload from sealed storage
	ctx := context.Background()
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Confirm node 0 works before "restart"
	_, err = cluster.Servers[0].PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
		CodeCommitment:  cluster.CodeCommitment,
		Round:           cluster.Round,
		Ciphertext:      ct.Bytes,
		GlobalPubKey:    globalPubKey,
		Label:           label,
		RequesterPubKey: requesterPubBytes,
	})
	require.NoError(t, err, "node 0 should decrypt before restart")

	// Clear the in-memory dist key share cache to simulate restart.
	// Replace with a fresh empty cache so Get returns (nil, false),
	// forcing PartialDecryptTDH2 to reload the share from sealed storage.
	cluster.Servers[0].DistKeyShareCache = store.NewDistKeyShareCache()

	// Node 0 should reload from sealed file and still succeed
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

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

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
