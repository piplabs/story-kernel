package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// buildValidProtoJustification constructs a pb.Justification with real kyber
// scalar and point bytes from a fresh random polynomial. The crypto content is
// not derived from the actual DKG session, so ProcessJustification will internally
// skip it; however, the proto itself passes ConvertToJustification without error.
func buildValidProtoJustification(t *testing.T) *pb.Justification {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()
	threshold := 2
	n := 3

	secret := suite.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.Point().Base())

	shares := priPoly.Shares(n)
	_, commits := pubPoly.Info()

	shareBytes, err := shares[0].V.MarshalBinary()
	require.NoError(t, err)

	commitmentPoints := make([]*pb.Point, len(commits))
	for i, c := range commits {
		bz, err := c.MarshalBinary()
		require.NoError(t, err)
		commitmentPoints[i] = &pb.Point{Data: bz}
	}

	return &pb.Justification{
		Index: 0,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("integration-test-session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("integration-inner-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: shareBytes},
				},
				Threshold:   uint32(threshold),
				Commitments: commitmentPoints,
			},
			Signature: []byte("integration-test-signature"),
		},
	}
}

// TestProcessJustification_AcceptsStructuredInput verifies that ProcessJustification
// handles a well-formed request after DKG completion without returning a hard error.
// The justification is not from a real DKG complaint, so the service internally
// skips it — but the RPC call must succeed with an empty response.
func TestProcessJustification_AcceptsStructuredInput(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
	})
	require.NoError(t, err, "ProcessJustification should not return error for structured input")
	require.NotNil(t, resp)
}

// TestProcessJustification_MultipleJustifications verifies that a batch of
// justifications can be submitted in a single call.
func TestProcessJustification_MultipleJustifications(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{
			buildValidProtoJustification(t),
			buildValidProtoJustification(t),
		},
	})
	require.NoError(t, err, "ProcessJustification should accept multiple justifications")
	require.NotNil(t, resp)
}

// TestProcessJustification_AllNodesAcceptInput verifies that every node in the
// cluster can handle a ProcessJustification call after DKG completes.
func TestProcessJustification_AllNodesAcceptInput(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()

	ctx := context.Background()
	j := buildValidProtoJustification(t)

	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessJustification(ctx, &pb.ProcessJustificationRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Justifications: []*pb.Justification{j},
		})
		require.NoError(t, err, "ProcessJustification failed for node %d", i)
		require.NotNil(t, resp, "node %d should return a response", i)
	}
}

// TestProcessJustification_Resharing_AcceptsStructuredInput verifies that
// ProcessJustification with is_resharing=true handles structured input gracefully.
func TestProcessJustification_Resharing_AcceptsStructuredInput(t *testing.T) {
	cluster := NewDKGTestCluster(t, 3, 2)
	defer cluster.Cleanup()

	cluster.RunFullDKG()
	runResharingRound2(t, cluster)

	ctx := context.Background()
	resp, err := cluster.Servers[0].ProcessJustification(ctx, &pb.ProcessJustificationRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
		Justifications: []*pb.Justification{buildValidProtoJustification(t)},
		IsResharing:    true,
	})
	require.NoError(t, err, "ProcessJustification (resharing) should not error for structured input")
	require.NotNil(t, resp)
}
