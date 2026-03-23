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

// =============================================================================
// ConvertToDeal tests
// =============================================================================

// TestConvertToDeal_ValidDeal verifies that a fully populated pb.Deal is converted
// correctly to a dkg.Deal with all fields preserved.
func TestConvertToDeal_ValidDeal(t *testing.T) {
	t.Parallel()

	pbDeal := &pb.Deal{
		Index: 3,
		Deal: &pb.EncryptedDeal{
			DhKey:     []byte("dh_key_data"),
			Signature: []byte("deal_sig"),
			Nonce:     []byte("nonce_data"),
			Cipher:    []byte("cipher_data"),
		},
		Signature: []byte("outer_sig"),
	}

	dkgDeal := types.ConvertToDeal(pbDeal)
	require.NotNil(t, dkgDeal)
	require.Equal(t, uint32(3), dkgDeal.Index)
	require.Equal(t, []byte("dh_key_data"), dkgDeal.Deal.DHKey)
	require.Equal(t, []byte("deal_sig"), dkgDeal.Deal.Signature)
	require.Equal(t, []byte("nonce_data"), dkgDeal.Deal.Nonce)
	require.Equal(t, []byte("cipher_data"), dkgDeal.Deal.Cipher)
	require.Equal(t, []byte("outer_sig"), dkgDeal.Signature)
}

// TestConvertToDeal_NilEncryptedDeal verifies that a Deal with nil inner deal
// produces a dkg.Deal with nil fields (no panic).
func TestConvertToDeal_NilEncryptedDeal(t *testing.T) {
	t.Parallel()

	pbDeal := &pb.Deal{
		Index:     0,
		Deal:      nil,
		Signature: []byte("sig"),
	}

	dkgDeal := types.ConvertToDeal(pbDeal)
	require.NotNil(t, dkgDeal)
	require.Equal(t, uint32(0), dkgDeal.Index)
	// When Deal is nil, GetDeal() returns nil, so inner fields should be nil
	require.Nil(t, dkgDeal.Deal.DHKey)
	require.Nil(t, dkgDeal.Deal.Signature)
	require.Nil(t, dkgDeal.Deal.Nonce)
	require.Nil(t, dkgDeal.Deal.Cipher)
}

// TestConvertToDeal_ZeroIndex verifies that zero index is preserved.
func TestConvertToDeal_ZeroIndex(t *testing.T) {
	t.Parallel()

	pbDeal := &pb.Deal{
		Index: 0,
		Deal: &pb.EncryptedDeal{
			DhKey: []byte("key"),
		},
		Signature: []byte("sig"),
	}

	dkgDeal := types.ConvertToDeal(pbDeal)
	require.Equal(t, uint32(0), dkgDeal.Index)
}

// =============================================================================
// ConvertToRespProto tests
// =============================================================================

// TestConvertToRespProto_ValidResponse verifies that a fully populated dkg.Response
// is converted correctly to a pb.Response with all fields preserved.
func TestConvertToRespProto_ValidResponse(t *testing.T) {
	t.Parallel()

	dkgResp := &dkg.Response{
		Index: 5,
		Response: &vss.Response{
			SessionID: []byte("session-123"),
			Index:     2,
			Status:    true,
			Signature: []byte("resp-sig"),
		},
	}

	pbResp := types.ConvertToRespProto(dkgResp)
	require.NotNil(t, pbResp)
	require.Equal(t, uint32(5), pbResp.GetIndex())
	require.Equal(t, []byte("session-123"), pbResp.GetVssResponse().GetSessionId())
	require.Equal(t, uint32(2), pbResp.GetVssResponse().GetIndex())
	require.True(t, pbResp.GetVssResponse().GetStatus())
	require.Equal(t, []byte("resp-sig"), pbResp.GetVssResponse().GetSignature())
}

// TestConvertToRespProto_ZeroIndex verifies that zero indices are preserved.
func TestConvertToRespProto_ZeroIndex(t *testing.T) {
	t.Parallel()

	dkgResp := &dkg.Response{
		Index: 0,
		Response: &vss.Response{
			SessionID: []byte("s"),
			Index:     0,
			Status:    false,
			Signature: []byte("sig"),
		},
	}

	pbResp := types.ConvertToRespProto(dkgResp)
	require.Equal(t, uint32(0), pbResp.GetIndex())
	require.Equal(t, uint32(0), pbResp.GetVssResponse().GetIndex())
	require.False(t, pbResp.GetVssResponse().GetStatus())
}

// TestConvertToRespProto_EmptySessionID verifies empty session ID is preserved.
func TestConvertToRespProto_EmptySessionID(t *testing.T) {
	t.Parallel()

	dkgResp := &dkg.Response{
		Index: 1,
		Response: &vss.Response{
			SessionID: []byte{},
			Index:     0,
			Status:    true,
			Signature: nil,
		},
	}

	pbResp := types.ConvertToRespProto(dkgResp)
	require.Empty(t, pbResp.GetVssResponse().GetSessionId())
}

// =============================================================================
// ConvertToVSSResp tests
// =============================================================================

// TestConvertToVSSResp_ValidResponse verifies that a fully populated pb.Response
// is converted correctly to a dkg.Response with all fields preserved.
func TestConvertToVSSResp_ValidResponse(t *testing.T) {
	t.Parallel()

	pbResp := &pb.Response{
		Index: 7,
		VssResponse: &pb.VSSResponse{
			SessionId: []byte("vss-session"),
			Index:     3,
			Status:    true,
			Signature: []byte("vss-sig"),
		},
	}

	dkgResp := types.ConvertToVSSResp(pbResp)
	require.NotNil(t, dkgResp)
	require.Equal(t, uint32(7), dkgResp.Index)
	require.Equal(t, []byte("vss-session"), dkgResp.Response.SessionID)
	require.Equal(t, uint32(3), dkgResp.Response.Index)
	require.True(t, dkgResp.Response.Status)
	require.Equal(t, []byte("vss-sig"), dkgResp.Response.Signature)
}

// TestConvertToVSSResp_NilVssResponse verifies that a Response with nil VSSResponse
// produces a dkg.Response with nil/zero inner fields (no panic).
func TestConvertToVSSResp_NilVssResponse(t *testing.T) {
	t.Parallel()

	pbResp := &pb.Response{
		Index:       0,
		VssResponse: nil,
	}

	dkgResp := types.ConvertToVSSResp(pbResp)
	require.NotNil(t, dkgResp)
	require.Equal(t, uint32(0), dkgResp.Index)
	// When VssResponse is nil, GetVssResponse() returns nil, so inner fields are zero/nil
	require.Nil(t, dkgResp.Response.SessionID)
	require.Equal(t, uint32(0), dkgResp.Response.Index)
	require.False(t, dkgResp.Response.Status)
	require.Nil(t, dkgResp.Response.Signature)
}

// TestConvertToVSSResp_ZeroFields verifies that zero values are preserved.
func TestConvertToVSSResp_ZeroFields(t *testing.T) {
	t.Parallel()

	pbResp := &pb.Response{
		Index: 0,
		VssResponse: &pb.VSSResponse{
			SessionId: nil,
			Index:     0,
			Status:    false,
			Signature: nil,
		},
	}

	dkgResp := types.ConvertToVSSResp(pbResp)
	require.Equal(t, uint32(0), dkgResp.Index)
	require.Equal(t, uint32(0), dkgResp.Response.Index)
	require.False(t, dkgResp.Response.Status)
}

// =============================================================================
// ConvertToRespProto → ConvertToVSSResp round-trip test
// =============================================================================

// TestConvertRespProto_RoundTrip verifies that converting a dkg.Response to proto
// and back produces an equivalent result.
func TestConvertRespProto_RoundTrip(t *testing.T) {
	t.Parallel()

	original := &dkg.Response{
		Index: 4,
		Response: &vss.Response{
			SessionID: []byte("round-trip-session"),
			Index:     2,
			Status:    true,
			Signature: []byte("round-trip-sig"),
		},
	}

	// Convert kyber → proto
	pbResp := types.ConvertToRespProto(original)

	// Convert proto → kyber
	recovered := types.ConvertToVSSResp(pbResp)

	require.Equal(t, original.Index, recovered.Index)
	require.Equal(t, original.Response.SessionID, recovered.Response.SessionID)
	require.Equal(t, original.Response.Index, recovered.Response.Index)
	require.Equal(t, original.Response.Status, recovered.Response.Status)
	require.Equal(t, original.Response.Signature, recovered.Response.Signature)
}

// TestConvertToDeal_RoundTrip_FieldsPreserved verifies that all fields
// of a Deal survive the proto→dkg conversion.
func TestConvertToDeal_RoundTrip_FieldsPreserved(t *testing.T) {
	t.Parallel()

	pbDeal := &pb.Deal{
		Index: 10,
		Deal: &pb.EncryptedDeal{
			DhKey:     []byte{0x01, 0x02, 0x03},
			Signature: []byte{0x04, 0x05},
			Nonce:     []byte{0x06, 0x07, 0x08, 0x09},
			Cipher:    []byte{0x0A, 0x0B, 0x0C},
		},
		Signature: []byte{0x0D, 0x0E},
	}

	dkgDeal := types.ConvertToDeal(pbDeal)

	// Verify all byte slices are independent copies or identical content
	require.Equal(t, pbDeal.GetIndex(), dkgDeal.Index)
	require.Equal(t, pbDeal.GetDeal().GetDhKey(), dkgDeal.Deal.DHKey)
	require.Equal(t, pbDeal.GetDeal().GetSignature(), dkgDeal.Deal.Signature)
	require.Equal(t, pbDeal.GetDeal().GetNonce(), dkgDeal.Deal.Nonce)
	require.Equal(t, pbDeal.GetDeal().GetCipher(), dkgDeal.Deal.Cipher)
	require.Equal(t, pbDeal.GetSignature(), dkgDeal.Signature)
}

// TestConvertToJustification_NilSecShareScalarValue verifies that a SecShare
// with nil V (scalar value) returns an error.
func TestConvertToJustification_NilSecShareScalarValue(t *testing.T) {
	t.Parallel()

	j := &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("pd-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: nil, // nil scalar
				},
				Threshold: 2,
			},
		},
	}

	result, err := types.ConvertToJustification(j)
	require.Error(t, err, "nil scalar value should return an error")
	require.Contains(t, err.Error(), "nil SecShare")
	require.Nil(t, result)
}

// TestConvertToJustification_EmptyScalarData verifies that empty scalar data
// (not nil SecShare, but empty Data in the Scalar) still triggers an error
// from the kyber unmarshal.
func TestConvertToJustification_EmptyScalarData(t *testing.T) {
	t.Parallel()

	j := &pb.Justification{
		Index: 1,
		VssJustification: &pb.VSSJustification{
			SessionId: []byte("session"),
			Index:     1,
			PlainDeal: &pb.PlainDeal{
				SessionId: []byte("pd-session"),
				SecShare: &pb.SecShare{
					I: 1,
					V: &pb.Scalar{Data: []byte{}},
				},
				Threshold: 2,
			},
		},
	}

	result, err := types.ConvertToJustification(j)
	require.Error(t, err, "empty scalar data should return an error")
	require.Contains(t, err.Error(), "failed to unmarshal secret share scalar")
	require.Nil(t, result)
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
