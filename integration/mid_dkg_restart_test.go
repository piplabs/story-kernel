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

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestMidDKGRestart_AfterProcessDeals verifies that a node that restarts after
// ProcessDeals but before ProcessResponses can still recover and complete the DKG.
//
// The service persists DKG state (deals) to disk during ProcessDeals, so GetInitDKG
// can rebuild the DistKeyGenerator from disk on the next call. All nodes — including
// the restarted one — can complete ProcessResponses and FinalizeDKG.
func TestMidDKGRestart_AfterProcessDeals(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals() // persists deals to disk on all nodes

	// Rebuild node 0: fresh in-memory state, sealed files on disk intact.
	// GetInitDKG will rebuild from the persisted deals on the next call.
	cluster.Servers[0] = rebuildServer(t, cluster, 0)

	ctx := context.Background()

	// Flatten all responses collected during ProcessAllDeals
	var allResps []*pb.Response
	for _, resps := range cluster.ProcessedResps {
		allResps = append(allResps, resps...)
	}

	// All nodes — including restarted node 0 — can complete ProcessResponses
	// because GetInitDKG rebuilds the DKG from persisted disk state.
	for i := range cluster.Servers {
		_, err := cluster.Servers[i].ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Responses:      allResps,
		})
		require.NoError(t, err, "ProcessResponses must succeed for node %d after restart", i)
	}

	resps := make([]*pb.FinalizeDKGResponse, len(cluster.Servers))
	for i := range cluster.Servers {
		resp, err := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, err, "FinalizeDKG must succeed for node %d after restart", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(),
			"node %d must produce a valid global_pub_key", i)
		resps[i] = resp
	}

	// Consistency check: all nodes must agree on global_pub_key
	globalPubKey := resps[0].GetGlobalPubKey()
	for i := 1; i < len(resps); i++ {
		require.True(t, bytes.Equal(globalPubKey, resps[i].GetGlobalPubKey()),
			"node %d global_pub_key differs from node 0 after restart", i)
	}

	// TDH2 end-to-end verification: prove the restarted node's share is functionally equivalent.
	// Manually set PIDCache for restarted node 0 (CachePID is only called during GenerateDeals).
	cluster.Servers[0].PIDCache.Set(cluster.Round, uint32(1))

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("mid-dkg-restart-after-process-deals")
	label := []byte("restart-test-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Collect partial decryptions from restarted node 0 and node 1
	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey,
		map[string][]byte{NodeName(0): result0.PubShare, NodeName(1): result1.PubShare},
		ct, label,
		map[string]*mpc.TDH2PartialDecryption{NodeName(0): result0.Partial, NodeName(1): result1.Partial},
	)
	require.NoError(t, err, "TDH2Combine must succeed with restarted node's partial")
	require.Equal(t, plaintext, decrypted, "decrypted text must match original after mid-DKG restart")
}

// TestMidDKGRestart_BeforeFinalizeDKG verifies that a node restarted after
// ProcessResponses (but before FinalizeDKG) can still finalize successfully.
//
// Both deals and responses are persisted to disk during their respective phases.
// After restart, GetInitDKG calls rebuildInitDKG which replays deals AND
// responses from dkg_state.json, restoring the DistKeyGenerator to a state
// where DistKeyShare() can succeed.
//
// Covers K-CACHE-03 from the code review.
func TestMidDKGRestart_BeforeFinalizeDKG(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()
	cluster.ProcessAllDeals()
	cluster.ProcessAllResponses() // deals + responses are now persisted to disk

	// Restart node 0: clear all in-memory caches, retain disk state.
	cluster.Servers[0] = rebuildServer(t, cluster, 0)

	ctx := context.Background()

	// All nodes — including restarted node 0 — should finalize successfully.
	// Node 0's GetInitDKG will rebuild from disk (replay deals + responses).
	resps := make([]*pb.FinalizeDKGResponse, len(cluster.Servers))
	for i := range cluster.Servers {
		resp, err := cluster.Servers[i].FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
		})
		require.NoError(t, err, "FinalizeDKG must succeed for node %d after restart", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(),
			"node %d must produce a valid global_pub_key", i)
		resps[i] = resp
	}

	// Consistency check: all nodes must agree on global_pub_key
	globalPubKey := resps[0].GetGlobalPubKey()
	for i := 1; i < len(resps); i++ {
		require.True(t, bytes.Equal(globalPubKey, resps[i].GetGlobalPubKey()),
			"node %d global_pub_key differs from node 0 after restart", i)
	}

	// TDH2 end-to-end verification: prove the restarted node's share is functionally equivalent.
	cluster.Servers[0].PIDCache.Set(cluster.Round, uint32(1))

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("mid-dkg-restart-before-finalize")
	label := []byte("restart-test-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	result0 := collectPartialDecrypt(t, cluster, 0, ct.Bytes, globalPubKey, label, requesterPriv)
	result1 := collectPartialDecrypt(t, cluster, 1, ct.Bytes, globalPubKey, label, requesterPriv)

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey,
		map[string][]byte{NodeName(0): result0.PubShare, NodeName(1): result1.PubShare},
		ct, label,
		map[string]*mpc.TDH2PartialDecryption{NodeName(0): result0.Partial, NodeName(1): result1.Partial},
	)
	require.NoError(t, err, "TDH2Combine must succeed with restarted node's partial")
	require.Equal(t, plaintext, decrypted, "decrypted text must match original after mid-DKG restart")
}
