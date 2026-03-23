package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// TestGetCodeCommitment_ReturnsValidCommitment verifies that GetCodeCommitment
// returns a non-empty code commitment matching the enclave's MRENCLAVE.
func TestGetCodeCommitment_ReturnsValidCommitment(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	resp, err := cluster.Servers[0].GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetCodeCommitment(), "code commitment should not be empty")
	require.Equal(t, cluster.CodeCommitment, resp.GetCodeCommitment(),
		"returned commitment must match the enclave's MRENCLAVE")
}

// TestGetCodeCommitment_Is32Bytes verifies that the returned code commitment is
// 32 bytes (matching the SGX MRENCLAVE size).
func TestGetCodeCommitment_Is32Bytes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	resp, err := cluster.Servers[0].GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetCodeCommitment(), 32, "MRENCLAVE should be exactly 32 bytes")
}

// TestGetCodeCommitment_ConsistentAcrossNodes verifies that all nodes in the cluster
// return the same code commitment (all share the same enclave build).
func TestGetCodeCommitment_ConsistentAcrossNodes(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	ctx := context.Background()
	commitments := make([][]byte, len(cluster.Servers))
	for i, srv := range cluster.Servers {
		resp, err := srv.GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
		require.NoError(t, err, "GetCodeCommitment failed for node %d", i)
		require.NotEmpty(t, resp.GetCodeCommitment(), "node %d: code commitment should not be empty", i)
		commitments[i] = resp.GetCodeCommitment()
	}

	// All nodes must return the same code commitment
	for i := 1; i < len(commitments); i++ {
		require.Equal(t, commitments[0], commitments[i],
			"node %d code commitment differs from node 0", i)
	}
}

// TestGetCodeCommitment_NoInputRequired verifies that GetCodeCommitment requires
// no input fields and accepts an empty request proto.
func TestGetCodeCommitment_NoInputRequired(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	// Empty request proto — no code_commitment or round needed
	resp, err := cluster.Servers[0].GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
	require.NoError(t, err, "GetCodeCommitment should accept an empty request")
	require.NotNil(t, resp)
}

// TestGetCodeCommitment_RepeatedCallsConsistent verifies that successive calls to
// GetCodeCommitment on the same node return the same value.
func TestGetCodeCommitment_RepeatedCallsConsistent(t *testing.T) {
	cluster := NewDKGTestCluster(t, 1, 1)
	defer cluster.Cleanup()

	ctx := context.Background()
	resp1, err := cluster.Servers[0].GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
	require.NoError(t, err)

	resp2, err := cluster.Servers[0].GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
	require.NoError(t, err)

	require.Equal(t, resp1.GetCodeCommitment(), resp2.GetCodeCommitment(),
		"successive calls must return the same code commitment")
}
