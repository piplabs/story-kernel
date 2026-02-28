package types_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"

	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// newSuite returns the Edwards25519 suite used by the DKG protocol.
func newSuite() *edwards25519.SuiteEd25519 {
	return edwards25519.NewBlakeSHA256Ed25519()
}

// generateKyberJustification creates a real kyber Justification using VSS polynomial
// arithmetic, suitable for round-trip conversion tests.
func generateKyberJustification(t *testing.T) *dkg.Justification {
	t.Helper()

	suite := newSuite()
	n := 3
	threshold := 2

	secret := suite.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.Point().Base())

	shares := priPoly.Shares(n)
	_, commits := pubPoly.Info()

	// Build the VSS Deal for recipient 1 (1-based)
	return &dkg.Justification{
		Index: 5,
		Justification: &vss.Justification{
			SessionID: []byte("test-session-id"),
			Index:     1,
			Deal: &vss.Deal{
				SessionID: []byte("inner-session-id"),
				SecShare: &share.PriShare{
					I: 1,
					V: shares[0].V,
				},
				T:           uint32(threshold),
				Commitments: commits,
			},
			Signature: []byte("test-signature"),
		},
	}
}

// buildProtoJustification constructs a minimal valid pb.Justification proto for
// testing error paths. Callers can selectively set fields to nil.
func buildProtoJustification(t *testing.T) *pb.Justification {
	t.Helper()

	suite := newSuite()
	n := 3
	threshold := 2

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
		Index: 5,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("test-session-id"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("inner-session-id"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: shareBytes},
				},
				Threshold:   uint32(threshold),
				Commitments: commitmentPoints,
			},
			Signature: []byte("test-signature"),
		},
	}
}

// TestConvertToJustificationProto_And_Back verifies the full round-trip:
// kyber Justification -> proto Justification -> kyber Justification,
// checking that key fields are preserved.
func TestConvertToJustificationProto_And_Back(t *testing.T) {
	t.Parallel()

	original := generateKyberJustification(t)

	// Convert kyber → proto
	proto, err := types.ConvertToJustificationProto(original)
	require.NoError(t, err)
	require.NotNil(t, proto)
	require.Equal(t, original.Index, proto.GetIndex())

	// Convert proto → kyber
	recovered, err := types.ConvertToJustification(proto)
	require.NoError(t, err)
	require.NotNil(t, recovered)

	// Verify dealer index is preserved
	require.Equal(t, original.Index, recovered.Index)

	// Verify session ID is preserved
	require.Equal(t, original.Justification.SessionID, recovered.Justification.SessionID)

	// Verify recipient index is preserved
	require.Equal(t, original.Justification.Deal.SecShare.I, recovered.Justification.Deal.SecShare.I)

	// Verify the scalar value round-trips correctly: marshal both and compare bytes
	origBytes, err := original.Justification.Deal.SecShare.V.MarshalBinary()
	require.NoError(t, err)
	recovBytes, err := recovered.Justification.Deal.SecShare.V.MarshalBinary()
	require.NoError(t, err)
	require.True(t, bytes.Equal(origBytes, recovBytes), "scalar values should be equal after round-trip")

	// Verify commitments count is preserved
	require.Len(t, recovered.Justification.Deal.Commitments, len(original.Justification.Deal.Commitments))

	// Verify commitments are equal by marshaling and comparing bytes
	for i, origCommit := range original.Justification.Deal.Commitments {
		oBz, err := origCommit.MarshalBinary()
		require.NoError(t, err)
		rBz, err := recovered.Justification.Deal.Commitments[i].MarshalBinary()
		require.NoError(t, err)
		require.True(t, bytes.Equal(oBz, rBz), "commitment[%d] should be equal after round-trip", i)
	}
}

// TestConvertToJustification_NilVSSJustification verifies that a nil VSSJustification
// field causes ConvertToJustification to return an error.
func TestConvertToJustification_NilVSSJustification(t *testing.T) {
	t.Parallel()

	j := &pb.Justification{
		Index:            1,
		VssJustification: nil,
	}

	result, err := types.ConvertToJustification(j)
	require.Error(t, err, "nil VSSJustification should return an error")
	require.Contains(t, err.Error(), "nil VSSJustification")
	require.Nil(t, result)
}

// TestConvertToJustification_NilPlainDeal verifies that a nil PlainDeal field
// causes ConvertToJustification to return an error.
func TestConvertToJustification_NilPlainDeal(t *testing.T) {
	t.Parallel()

	j := &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session"),
			Index:     1,
			PlainDeal: nil,
		},
	}

	result, err := types.ConvertToJustification(j)
	require.Error(t, err, "nil PlainDeal should return an error")
	require.Contains(t, err.Error(), "nil PlainDeal")
	require.Nil(t, result)
}

// TestConvertToJustification_NilSecShare verifies that a nil SecShare field
// causes ConvertToJustification to return an error.
func TestConvertToJustification_NilSecShare(t *testing.T) {
	t.Parallel()

	j := &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("pd-session"),
				SecShare:  nil,
				Threshold: 2,
			},
		},
	}

	result, err := types.ConvertToJustification(j)
	require.Error(t, err, "nil SecShare should return an error")
	require.Contains(t, err.Error(), "nil SecShare")
	require.Nil(t, result)
}

// TestConvertToJustification_InvalidScalarBytes verifies that malformed scalar
// bytes cause ConvertToJustification to return an error.
func TestConvertToJustification_InvalidScalarBytes(t *testing.T) {
	t.Parallel()

	// Get valid commitments to ensure the error is from the scalar, not commitments
	protoJ := buildProtoJustification(t)
	// Replace the scalar with garbage bytes
	protoJ.VssJustification.PlainDeal.SecShare.V.Data = []byte("this-is-not-a-valid-scalar-byte-sequence")

	result, err := types.ConvertToJustification(protoJ)
	require.Error(t, err, "invalid scalar bytes should return an error")
	require.Contains(t, err.Error(), "failed to unmarshal secret share scalar")
	require.Nil(t, result)
}

// TestConvertToJustification_InvalidPointBytes verifies that malformed commitment
// point bytes cause ConvertToJustification to return an error.
func TestConvertToJustification_InvalidPointBytes(t *testing.T) {
	t.Parallel()

	protoJ := buildProtoJustification(t)
	// Replace the first commitment point with garbage bytes
	protoJ.VssJustification.PlainDeal.Commitments[0].Data = []byte("not-a-valid-ed25519-point")

	result, err := types.ConvertToJustification(protoJ)
	require.Error(t, err, "invalid commitment point bytes should return an error")
	require.Contains(t, err.Error(), "failed to unmarshal commitment point")
	require.Nil(t, result)
}

// TestConvertToJustification_ValidData verifies that a properly formed proto
// Justification is successfully converted without error.
func TestConvertToJustification_ValidData(t *testing.T) {
	t.Parallel()

	protoJ := buildProtoJustification(t)

	result, err := types.ConvertToJustification(protoJ)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, protoJ.GetIndex(), result.Index)
	require.Equal(t, protoJ.VssJustification.GetSessionId(), result.Justification.SessionID)
	require.Equal(t, int(protoJ.VssJustification.PlainDeal.SecShare.GetI()), result.Justification.Deal.SecShare.I)
}

// TestConvertToJustificationProto_ValidKyber verifies that a valid kyber
// Justification can be serialized to proto without error.
func TestConvertToJustificationProto_ValidKyber(t *testing.T) {
	t.Parallel()

	kyberJ := generateKyberJustification(t)

	protoJ, err := types.ConvertToJustificationProto(kyberJ)
	require.NoError(t, err)
	require.NotNil(t, protoJ)
	require.Equal(t, kyberJ.Index, protoJ.GetIndex())
	require.Equal(t, kyberJ.Justification.SessionID, protoJ.VssJustification.GetSessionId())
	require.Len(t, protoJ.VssJustification.PlainDeal.Commitments, len(kyberJ.Justification.Deal.Commitments))
}

// TestConvertToJustification_MultipleCommitments verifies that a justification
// with multiple commitment points (threshold > 2) round-trips correctly.
func TestConvertToJustification_MultipleCommitments(t *testing.T) {
	t.Parallel()

	suite := newSuite()
	n := 5
	threshold := 4

	secret := suite.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.Point().Base())

	shares := priPoly.Shares(n)
	_, commits := pubPoly.Info()
	require.Len(t, commits, threshold, "should have threshold commitments")

	shareBytes, err := shares[0].V.MarshalBinary()
	require.NoError(t, err)

	commitmentPoints := make([]*pb.Point, len(commits))
	for i, c := range commits {
		bz, err := c.MarshalBinary()
		require.NoError(t, err)
		commitmentPoints[i] = &pb.Point{Data: bz}
	}

	protoJ := &pb.Justification{
		Index: 10,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("multi-commit-session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("multi-commit-inner"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: shareBytes},
				},
				Threshold:   uint32(threshold),
				Commitments: commitmentPoints,
			},
			Signature: []byte("sig"),
		},
	}

	result, err := types.ConvertToJustification(protoJ)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Justification.Deal.Commitments, threshold,
		"all %d commitments should be converted", threshold)
}

// TestConvertToJustification_IndexConventionEndToEnd creates actual kyber DKG
// DistKeyGenerators, performs a full deal/response exchange, and verifies that:
//  1. All DKG-level indices (Deal.Index, Response.Index) are 0-based
//  2. All VSS-level indices (Response.Response.Index) are 0-based
//  3. Proto conversion preserves 0-based indices exactly
//  4. The share data from a justification verifies at the correct evaluation point
//
// This is the definitive test proving that the entire pipeline uses 0-based
// indices from kyber through proto to on-chain verification.
func TestConvertToJustification_IndexConventionEndToEnd(t *testing.T) {
	t.Parallel()

	suite := newSuite()
	n := 5
	threshold := 3

	// Step 1: Create N key pairs and DKG generators (real DKG setup)
	privKeys := make([]kyber.Scalar, n)
	pubKeys := make([]kyber.Point, n)
	dkgs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		privKeys[i] = suite.Scalar().Pick(suite.RandomStream())
		pubKeys[i] = suite.Point().Mul(privKeys[i], nil)
	}
	for i := 0; i < n; i++ {
		var err error
		dkgs[i], err = dkg.NewDistKeyGenerator(suite, privKeys[i], pubKeys, threshold)
		require.NoError(t, err)
	}

	// Step 2: Full deal exchange — verify all indices are 0-based
	allResps := make([]*dkg.Response, 0)
	for dealerIdx, d := range dkgs {
		deals, err := d.Deals()
		require.NoError(t, err)

		for recipientIdx, deal := range deals {
			// DKG Deal.Index = dealer's 0-based index
			require.Equal(t, uint32(dealerIdx), deal.Index,
				"Deal.Index should be 0-based dealer index %d", dealerIdx)

			resp, err := dkgs[recipientIdx].ProcessDeal(deal)
			require.NoError(t, err)

			// DKG Response.Index = dealer's 0-based index (whose deal this responds to)
			require.Equal(t, uint32(dealerIdx), resp.Index,
				"Response.Index should be 0-based dealer index %d", dealerIdx)

			// VSS Response.Index = verifier's 0-based index
			require.Equal(t, uint32(recipientIdx), resp.Response.Index,
				"VSS Response.Index should be 0-based verifier index %d", recipientIdx)

			allResps = append(allResps, resp)
		}
	}

	// Step 3: Process all responses
	for _, resp := range allResps {
		for i, d := range dkgs {
			if resp.Response.Index == uint32(i) {
				continue
			}
			_, err := d.ProcessResponse(resp)
			require.NoError(t, err)
		}
	}

	// Step 4: Verify DKG succeeded
	for i, d := range dkgs {
		_, err := d.DistKeyShare()
		require.NoError(t, err, "participant %d should have valid dist key share", i)
	}

	// Step 5: Construct a justification with known 0-based indices
	// (using real polynomial data, simulating what kyber internally produces)
	secret := suite.Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite, threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.Point().Base())

	_, commits := pubPoly.Info()
	shares := priPoly.Shares(n)

	// Verify PriPoly.Shares returns 0-based indices
	for i, s := range shares {
		require.Equal(t, i, s.I,
			"PriPoly.Shares()[%d].I should be %d (0-based)", i, i)
	}

	// Step 6: Build a kyber justification with 0-based indices (dealer=2, verifier=3)
	dealerIndex := uint32(2)
	verifierIndex := uint32(3)
	kyberJust := &dkg.Justification{
		Index: dealerIndex, // 0-based dealer index
		Justification: &vss.Justification{
			SessionID: []byte("test-session"),
			Index:     verifierIndex, // 0-based verifier index
			Deal: &vss.Deal{
				SessionID: []byte("test-deal-session"),
				SecShare: &share.PriShare{
					I: int(verifierIndex), // 0-based, matches kyber's Eval(verifierIndex)
					V: shares[verifierIndex].V,
				},
				T:           uint32(threshold),
				Commitments: commits,
			},
			Signature: []byte("test-sig"),
		},
	}

	// Step 7: Convert kyber → proto → kyber and verify indices are preserved as 0-based
	protoJust, err := types.ConvertToJustificationProto(kyberJust)
	require.NoError(t, err)

	// Proto should have 0-based indices
	require.Equal(t, dealerIndex, protoJust.GetIndex(),
		"proto dealer index should be 0-based")
	require.Equal(t, verifierIndex, protoJust.GetVssJustification().GetIndex(),
		"proto VSS verifier index should be 0-based")
	require.Equal(t, verifierIndex, protoJust.GetVssJustification().GetPlainDeal().GetSecShare().GetI(),
		"proto SecShare.I should be 0-based")

	// Convert back to kyber
	recovered, err := types.ConvertToJustification(protoJust)
	require.NoError(t, err)

	// Recovered should have identical 0-based indices
	require.Equal(t, dealerIndex, recovered.Index,
		"recovered dealer index should be 0-based")
	require.Equal(t, verifierIndex, recovered.Justification.Index,
		"recovered VSS verifier index should be 0-based")
	require.Equal(t, int(verifierIndex), recovered.Justification.Deal.SecShare.I,
		"recovered SecShare.I should be 0-based")

	// Step 8: Verify that kyber's PubPoly.Check uses the same 0-based convention
	// PubPoly.Check internally calls Eval(s.I) which computes x = 1 + int64(s.I)
	pubPolyObj := share.NewPubPoly(suite, suite.Point().Base(), commits)
	checkResult := pubPolyObj.Check(recovered.Justification.Deal.SecShare)
	require.True(t, checkResult,
		"PubPoly.Check with 0-based PriShare.I=%d should pass", recovered.Justification.Deal.SecShare.I)

	// Verify wrong index fails
	wrongShare := &share.PriShare{
		I: int(verifierIndex) + 1, // shifted by 1 — wrong
		V: recovered.Justification.Deal.SecShare.V,
	}
	wrongResult := pubPolyObj.Check(wrongShare)
	require.False(t, wrongResult,
		"PubPoly.Check with wrong index %d should fail", wrongShare.I)
}

// TestConvertToJustification_EmptyCommitments verifies that zero commitments
// are handled without error (edge case: threshold=1, only the constant term).
func TestConvertToJustification_EmptyCommitments(t *testing.T) {
	t.Parallel()

	suite := newSuite()
	scalar := suite.Scalar().Pick(suite.RandomStream())
	shareBytes, err := scalar.MarshalBinary()
	require.NoError(t, err)

	protoJ := &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("pd-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: shareBytes},
				},
				Threshold:   1,
				Commitments: nil, // No commitments
			},
			Signature: []byte("sig"),
		},
	}

	result, err := types.ConvertToJustification(protoJ)
	require.NoError(t, err, "zero commitments should not error during conversion")
	require.NotNil(t, result)
	require.Empty(t, result.Justification.Deal.Commitments)
}
