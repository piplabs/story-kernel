package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestConcurrent_PartialDecryptSameNode verifies that 5 goroutines concurrently calling
// PartialDecryptTDH2 on the same node each receive a correct, independently verifiable result.
func TestConcurrent_PartialDecryptSameNode(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	const numRequesters = 5

	type requesterData struct {
		priv      *ecdsa.PrivateKey
		ct        *mpc.TDH2Ciphertext
		plaintext []byte
		label     []byte
		result    *partialDecryptResult
	}

	// Set up each requester with a unique key, plaintext, and ciphertext (sequential)
	data := make([]requesterData, numRequesters)
	for i := range numRequesters {
		priv, genErr := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
		require.NoError(t, genErr)

		plaintext := []byte(fmt.Sprintf("concurrent-%d", i))
		label := []byte(fmt.Sprintf("label-%d", i))

		ct, encErr := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
		require.NoError(t, encErr)

		data[i] = requesterData{priv: priv, ct: ct, plaintext: plaintext, label: label}
	}

	// 5 goroutines all call node 0 concurrently
	errs := make([]error, numRequesters)
	var wg sync.WaitGroup
	wg.Add(numRequesters)

	for i := range numRequesters {
		go func(idx int) {
			defer wg.Done()
			result, err := tryCollectPartialDecrypt(cluster, 0, data[idx].ct.Bytes, globalPubKey, data[idx].label, data[idx].priv)
			if err != nil {
				errs[idx] = err
				return
			}
			data[idx].result = result
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}

	// Verify each result: get a second partial from node 1 and combine
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	for i := range numRequesters {
		result1 := collectPartialDecrypt(t, cluster, 1, data[i].ct.Bytes, globalPubKey, data[i].label, data[i].priv)

		pubShares := map[string][]byte{
			NodeName(0): data[i].result.PubShare,
			NodeName(1): result1.PubShare,
		}
		pdMap := map[string]*mpc.TDH2PartialDecryption{
			NodeName(0): data[i].result.Partial,
			NodeName(1): result1.Partial,
		}

		decrypted, combineErr := mpc.TDH2Combine(as, tdh2PubKey, pubShares, data[i].ct, data[i].label, pdMap)
		require.NoError(t, combineErr, "combine failed for requester %d", i)
		require.Equal(t, data[i].plaintext, decrypted, "decrypted mismatch for requester %d", i)
	}
}

// TestConcurrent_PartialDecryptAllNodes verifies that a single requester can concurrently
// fan out PartialDecryptTDH2 to all 3 nodes and correctly combine the collected results.
func TestConcurrent_PartialDecryptAllNodes(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("fan-out concurrent test")
	label := []byte("fanout-label")

	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Fan out to all 3 nodes concurrently; each goroutine writes to its own index
	results := make([]*partialDecryptResult, 3)
	errs := make([]error, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	for i := range 3 {
		go func(idx int) {
			defer wg.Done()
			result, err := tryCollectPartialDecrypt(cluster, idx, ct.Bytes, globalPubKey, label, requesterPriv)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = result
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}

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

// TestConcurrent_MultipleRequesters verifies that 3 independent requesters concurrently
// querying all nodes produce isolated results with no cross-contamination.
func TestConcurrent_MultipleRequesters(t *testing.T) {
	cluster := runTDH2Setup(t)
	defer cluster.Cleanup()

	globalPubKey := cluster.FinalizeResps[0].GetGlobalPubKey()

	// Use a single key for encryption only — all encryptions happen sequentially before goroutines start
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	const numRequesters = 3

	type requesterSetup struct {
		priv      *ecdsa.PrivateKey
		ct        *mpc.TDH2Ciphertext
		plaintext []byte
		label     []byte
	}

	setups := make([]requesterSetup, numRequesters)
	for i := range numRequesters {
		priv, genErr := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
		require.NoError(t, genErr)

		plaintext := []byte(fmt.Sprintf("requester-%d-secret", i))
		label := []byte(fmt.Sprintf("requester-%d-label", i))

		ct, encErr := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
		require.NoError(t, encErr)

		setups[i] = requesterSetup{priv: priv, ct: ct, plaintext: plaintext, label: label}
	}

	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}

	// 3 requesters fan out concurrently — collect errors instead of using require in goroutines
	outerErrs := make([]error, numRequesters)
	var outerWg sync.WaitGroup
	outerWg.Add(numRequesters)

	for r := range numRequesters {
		go func(rIdx int) {
			defer outerWg.Done()

			// Each requester builds its own TDH2 key and access structure to avoid shared mutable state
			localPubKey, pkErr := buildTDH2PubKey(globalPubKey)
			if pkErr != nil {
				outerErrs[rIdx] = fmt.Errorf("requester %d: buildTDH2PubKey: %w", rIdx, pkErr)
				return
			}
			defer localPubKey.Free()

			localAS, asErr := buildTDH2AccessStructure(2, nodeNames)
			if asErr != nil {
				outerErrs[rIdx] = fmt.Errorf("requester %d: buildTDH2AccessStructure: %w", rIdx, asErr)
				return
			}

			// Concurrently query nodes 0 and 1; each inner goroutine writes to its own index
			results := make([]*partialDecryptResult, 2)
			innerErrs := make([]error, 2)
			var innerWg sync.WaitGroup
			innerWg.Add(2)

			for j, nodeIdx := range []int{0, 1} {
				go func(jIdx, nIdx int) {
					defer innerWg.Done()
					result, err := tryCollectPartialDecrypt(cluster, nIdx,
						setups[rIdx].ct.Bytes, globalPubKey, setups[rIdx].label, setups[rIdx].priv)
					if err != nil {
						innerErrs[jIdx] = err
						return
					}
					results[jIdx] = result
				}(j, nodeIdx)
			}
			innerWg.Wait()

			for j, err := range innerErrs {
				if err != nil {
					outerErrs[rIdx] = fmt.Errorf("requester %d inner goroutine %d: %w", rIdx, j, err)
					return
				}
			}

			pubShares := map[string][]byte{
				NodeName(0): results[0].PubShare,
				NodeName(1): results[1].PubShare,
			}
			pdMap := map[string]*mpc.TDH2PartialDecryption{
				NodeName(0): results[0].Partial,
				NodeName(1): results[1].Partial,
			}

			decrypted, combineErr := mpc.TDH2Combine(localAS, localPubKey, pubShares, setups[rIdx].ct, setups[rIdx].label, pdMap)
			if combineErr != nil {
				outerErrs[rIdx] = fmt.Errorf("requester %d: combine: %w", rIdx, combineErr)
				return
			}
			if string(decrypted) != string(setups[rIdx].plaintext) {
				outerErrs[rIdx] = fmt.Errorf("requester %d: wrong plaintext: got %q, want %q", rIdx, decrypted, setups[rIdx].plaintext)
			}
		}(r)
	}
	outerWg.Wait()

	for i, err := range outerErrs {
		require.NoError(t, err, "requester %d failed", i)
	}
}

// TestConcurrent_GenerateDealsAllNodes verifies that all 3 nodes can call GenerateDeals
// concurrently and the resulting deal responses can drive a complete DKG to finalization.
// This exercises thread safety of the kyber suite and InitDKGCache under parallel writes.
func TestConcurrent_GenerateDealsAllNodes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()

	ctx := context.Background()
	n := len(cluster.Servers)

	dealResps := make([]*pb.GenerateDealsResponse, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)

	// All nodes call GenerateDeals concurrently; each goroutine writes to its own index.
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			resp, err := cluster.Servers[idx].GenerateDeals(ctx, &pb.GenerateDealsRequest{
				CodeCommitment: cluster.CodeCommitment,
				Round:          cluster.Round,
			})
			if err != nil {
				errs[idx] = fmt.Errorf("concurrent GenerateDeals failed for node %d: %w", idx, err)
				return
			}
			dealResps[idx] = resp
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}

	// Use the concurrently-collected deal responses to complete DKG
	cluster.DealResponses = dealResps
	cluster.ProcessAllDeals()
	cluster.ProcessAllResponses()
	cluster.FinalizeAll()

	require.NotEmpty(t, cluster.FinalizeResps[0].GetGlobalPubKey(),
		"GlobalPubKey must be non-empty after DKG driven by concurrently-generated deals")
}

// TestConcurrent_ProcessDealsAllNodes verifies that all 3 nodes can call ProcessDeals
// concurrently. Each node processes its own deal bundle independently, so there is no
// shared state between goroutines; the test confirms no data race occurs across nodes.
func TestConcurrent_ProcessDealsAllNodes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()
	cluster.GenerateAllDeals()

	ctx := context.Background()
	n := len(cluster.Servers)

	// Pre-compute per-recipient deal bundles sequentially
	dealsByRecipient := buildDealsByRecipient(t, n, cluster.DealResponses)

	processedResps := make([][]*pb.Response, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)

	// All nodes call ProcessDeals concurrently; each goroutine writes to its own index.
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			resp, err := cluster.Servers[idx].ProcessDeals(ctx, &pb.ProcessDealsRequest{
				CodeCommitment: cluster.CodeCommitment,
				Round:          cluster.Round,
				Deals:          dealsByRecipient[idx],
			})
			if err != nil {
				errs[idx] = fmt.Errorf("concurrent ProcessDeals failed for node %d: %w", idx, err)
				return
			}
			processedResps[idx] = resp.GetResponses()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}

	// Store results and complete DKG
	cluster.ProcessedResps = processedResps
	cluster.ProcessAllResponses()
	cluster.FinalizeAll()

	require.NotEmpty(t, cluster.FinalizeResps[0].GetGlobalPubKey(),
		"GlobalPubKey must be non-empty after DKG driven by concurrently-processed deals")
}
