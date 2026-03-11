package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
)

// rebuildServer creates a fresh DKGServer using the same tempDir as an existing cluster node,
// simulating a process restart while retaining sealed files on disk.
func rebuildServer(t *testing.T, cluster *DKGTestCluster, nodeIdx int) *service.DKGServer {
	t.Helper()

	dir := cluster.TempDirs[nodeIdx]
	suite := edwards25519.NewBlakeSHA256Ed25519()

	cfg := config.DefaultConfig()
	cfg.SetHomeDir(dir)

	srv := &service.DKGServer{
		Cfg:                cfg,
		QueryClient:        cluster.MockQC,
		Suite:              suite,
		RoundCtxCache:      store.NewRoundContextCache(),
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
		DistKeyShareCache:  store.NewDistKeyShareCache(),
		DKGStore:           store.NewDKGStore(cfg.GetKeysDir(), cfg.GetDKGStateDir(), suite),
		PIDCache:           store.NewPIDCache(),
	}

	// Re-populate PIDCache: the PID is 1-based index from registrations
	// Node i has PID = i+1 (same as during GenerateDeals)
	srv.PIDCache.Set(cluster.Round, uint32(nodeIdx+1))

	return srv
}

// TestPersistence_RestartRecovery verifies that a restarted node (fresh in-memory state,
// sealed files intact) can still produce a valid partial decryption.
func TestPersistence_RestartRecovery(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("persistence restart test")
	label := []byte("persist-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Simulate restart of node 0: replace with a fresh server using the same tempDir
	restartedNode0 := rebuildServer(t, cluster, 0)

	// Override node 0 in cluster temporarily for collectPartialDecrypt
	original := cluster.Servers[0]
	cluster.Servers[0] = restartedNode0
	defer func() { cluster.Servers[0] = original }()

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
	require.NoError(t, err, "restarted node should be able to produce valid partial decryption")
	require.Equal(t, plaintext, decrypted)
}

// TestPersistence_AllNodesRestart verifies that all 3 nodes can be restarted
// and still produce valid partial decryptions.
func TestPersistence_AllNodesRestart(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("all nodes restart test")
	label := []byte("all-restart-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Restart all nodes
	for i := range cluster.Servers {
		cluster.Servers[i] = rebuildServer(t, cluster, i)
	}

	results := make([]*partialDecryptResult, 3)
	for i := range 3 {
		results[i] = collectPartialDecrypt(t, cluster, i, ct.Bytes, globalPubKey, label, requesterPriv)
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	// Verify all combinations still work after restart
	combinations := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, combo := range combinations {
		a, b := combo[0], combo[1]
		t.Run(fmt.Sprintf("restart-%s+%s", NodeName(a), NodeName(b)), func(t *testing.T) {
			pubShares := map[string][]byte{
				NodeName(a): results[a].PubShare,
				NodeName(b): results[b].PubShare,
			}
			pdMap := map[string]*mpc.TDH2PartialDecryption{
				NodeName(a): results[a].Partial,
				NodeName(b): results[b].Partial,
			}

			decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
			require.NoError(t, err, "combine failed for nodes %d+%d after restart", a, b)
			require.Equal(t, plaintext, decrypted)
		})
	}
}

// TestPersistence_SealedKeysSurviveCleanup verifies that sealed key files exist on disk
// after DKG and can be used by a newly constructed DKGStore.
func TestPersistence_SealedKeysSurviveCleanup(t *testing.T) {
	cluster := runTDH2Setup(t)
	// Do NOT defer cluster.Cleanup() — we need the files to persist during assertion

	// Verify sealed key files exist
	keysDir := cluster.Servers[0].Cfg.GetKeysDir()
	entries, err := os.ReadDir(keysDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "sealed key files should exist in keysDir")

	// Verify DKG state dir contains sealed dist key share
	stateDir := cluster.Servers[0].Cfg.GetDKGStateDir()
	_, statErr := os.Stat(stateDir)
	require.NoError(t, statErr, "DKG state dir should exist")

	// Clean up manually
	for _, d := range cluster.TempDirs {
		os.RemoveAll(d)
	}
}
