package service

import (
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"

	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func TestValidateProcessResponsesRequest_MissingRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          0,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "round should be greater than 0")
}

func TestValidateProcessResponsesRequest_MissingCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: nil,
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code commitment is required but missing")
}

func TestValidateProcessResponsesRequest_EmptyResponses(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      nil,
	}

	err := validateProcessResponsesRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty responses to process")
}

func TestValidateProcessResponsesRequest_Valid(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessResponsesRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Responses:      []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}},
	}

	err := validateProcessResponsesRequest(req)
	require.NoError(t, err)
}

func TestValidateProcessResponsesRequest_TableDriven(t *testing.T) {
	t.Parallel()

	validCC := []byte("32-byte-code-commitment-padding!!")
	validResps := []*pb.Response{{Index: 1, VssResponse: &pb.VSSResponse{}}}

	tests := []struct {
		name           string
		round          uint32
		codeCommitment []byte
		responses      []*pb.Response
		wantErr        bool
		errContains    string
	}{
		{
			name:           "all fields valid",
			round:          1,
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        false,
		},
		{
			name:           "round is zero",
			round:          0,
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        true,
			errContains:    "round should be greater than 0",
		},
		{
			name:           "code commitment is nil",
			round:          1,
			codeCommitment: nil,
			responses:      validResps,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "code commitment is empty",
			round:          1,
			codeCommitment: []byte{},
			responses:      validResps,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "responses is nil",
			round:          1,
			codeCommitment: validCC,
			responses:      nil,
			wantErr:        true,
			errContains:    "empty responses to process",
		},
		{
			name:           "responses is empty slice",
			round:          1,
			codeCommitment: validCC,
			responses:      []*pb.Response{},
			wantErr:        true,
			errContains:    "empty responses to process",
		},
		{
			name:           "max round value",
			round:          ^uint32(0),
			codeCommitment: validCC,
			responses:      validResps,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &pb.ProcessResponsesRequest{
				Round:          tc.round,
				CodeCommitment: tc.codeCommitment,
				Responses:      tc.responses,
			}

			err := validateProcessResponsesRequest(req)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestSignResharingJustification_ResharingSignsAndVerifies proves the fix for
// issue #85: kyber's processResharingResponse returns an UNSIGNED justification
// (dealer key rotated out of the new committee, so newPresent=false), and
// signResharingJustification signs it with the dealer's prev-round key over the
// exact hash the CL verifies against the dealer's prev-round dkgPubKey.
func TestSignResharingJustification_ResharingSignsAndVerifies(t *testing.T) {
	t.Parallel()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	const nOld, threshold = 3, 2
	c := runCertifiedInitialDKG(t, nOld, threshold)

	// New committee uses fresh (rotated) keys, so every old dealer has
	// newPresent=false and routes responses through processResharingResponse.
	const nNew = 3
	newLong := make([]kyber.Scalar, nNew)
	newPubs := make([]kyber.Point, nNew)
	for i := 0; i < nNew; i++ {
		newLong[i] = suite.Scalar().Pick(suite.RandomStream())
		newPubs[i] = suite.Point().Mul(newLong[i], nil)
	}

	const dealerIdx, verifierIdx = 0, 0

	share, err := c.gens[dealerIdx].DistKeyShare()
	require.NoError(t, err)

	prevHandler, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        suite,
		Longterm:     c.longterms[dealerIdx],
		OldNodes:     c.pubs,
		NewNodes:     newPubs,
		Share:        share,
		Threshold:    threshold,
		OldThreshold: threshold,
	})
	require.NoError(t, err)

	// Dealer emits its resharing deals, as in production, before handling responses.
	_, err = prevHandler.Deals()
	require.NoError(t, err)

	// Craft a StatusComplaint from new-committee verifier 0 against the dealer's own
	// deal (outer Index = dealer's old index). The dealer's fresh empty aggregator
	// has no sessionID yet, so it only checks the verifier's Schnorr signature — the
	// cheapest way to drive processResharingResponse to emit an unsigned justification.
	vresp := &vss.Response{Index: verifierIdx, Status: vss.StatusComplaint}
	vresp.Signature, err = schnorr.Sign(suite, newLong[verifierIdx], vresp.Hash(suite))
	require.NoError(t, err)

	j, err := prevHandler.ProcessResponse(&dkg.Response{Index: dealerIdx, Response: vresp})
	require.NoError(t, err)
	require.NotNil(t, j)
	require.Empty(t, j.Justification.Signature, "kyber must leave the resharing justification unsigned (the bug)")

	// Apply the fix with the dealer's prev-round longterm key.
	require.NoError(t, signResharingJustification(suite, c.longterms[dealerIdx], j))
	require.NotEmpty(t, j.Justification.Signature)

	// Verify exactly as the CL does: convert to proto, reconstruct, hash, verify
	// against the dealer's prev-round dkgPubKey.
	pbJ, err := types.ConvertToJustificationProto(j)
	require.NoError(t, err)
	require.NotEmpty(t, pbJ.GetVssJustification().GetSignature(), "signature must propagate into the proto field")

	kyberJ, err := types.ConvertToJustification(pbJ)
	require.NoError(t, err)
	require.NoError(t, schnorr.Verify(suite, c.pubs[dealerIdx], kyberJ.Justification.Hash(suite), kyberJ.Justification.Signature))
}

// verifyJustificationLikeStoryClient replicates the story chain's
// verifyJustificationSignature (client/x/dkg/keeper/dkg_justification.go): it
// reconstructs the kyber vss.Justification from the proto fields — NOT via the
// kernel's own ConvertToJustification — computes the canonical hash, and Schnorr-
// verifies against the dealer pubkey. This pins that a justification the kernel
// signs passes the EXACT on-chain verification path, catching any divergence
// between the kernel converter and the CL's manual reconstruction.
func verifyJustificationLikeStoryClient(suite *edwards25519.SuiteEd25519, pbJ *pb.Justification, dealerPub kyber.Point) error {
	vssJ := pbJ.GetVssJustification()
	if vssJ == nil {
		return errors.New("nil VSSJustification")
	}
	plainDeal := vssJ.GetPlainDeal()
	if plainDeal == nil {
		return errors.New("nil PlainDeal")
	}
	secShare := plainDeal.GetSecShare()
	if secShare == nil || secShare.GetV() == nil {
		return errors.New("nil SecShare or scalar value")
	}
	if len(vssJ.GetSignature()) == 0 {
		return errors.New("empty justification signature")
	}

	shareScalar := suite.Scalar()
	if err := shareScalar.UnmarshalBinary(secShare.GetV().GetData()); err != nil {
		return errors.Wrap(err, "unmarshal share scalar")
	}

	commitments := make([]kyber.Point, 0, len(plainDeal.GetCommitments()))
	for _, cc := range plainDeal.GetCommitments() {
		p := suite.Point()
		if err := p.UnmarshalBinary(cc.GetData()); err != nil {
			return errors.Wrap(err, "unmarshal commitment point")
		}
		commitments = append(commitments, p)
	}

	kyberJust := &vss.Justification{
		SessionID: vssJ.GetSessionId(),
		Index:     vssJ.GetIndex(),
		Deal: &vss.Deal{
			SessionID: plainDeal.GetSessionId(),
			SecShare: &share.PriShare{
				I: int(secShare.GetI()),
				V: shareScalar,
			},
			T:           plainDeal.GetThreshold(),
			Commitments: commitments,
		},
		Signature: vssJ.GetSignature(),
	}

	return schnorr.Verify(suite, dealerPub, kyberJust.Hash(suite), kyberJust.Signature)
}

// TestSignResharingJustification_PassesStoryClientVerification proves a kernel-
// signed resharing justification verifies under the story chain's exact
// reconstruction+verify logic (not the kernel's own converter), and that the
// check rejects a tampered signature.
func TestSignResharingJustification_PassesStoryClientVerification(t *testing.T) {
	t.Parallel()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	const nOld, threshold, nNew = 3, 2, 3
	c := runCertifiedInitialDKG(t, nOld, threshold)

	newLong := make([]kyber.Scalar, nNew)
	newPubs := make([]kyber.Point, nNew)
	for i := 0; i < nNew; i++ {
		newLong[i] = suite.Scalar().Pick(suite.RandomStream())
		newPubs[i] = suite.Point().Mul(newLong[i], nil)
	}

	const dealerIdx, verifierIdx = 0, 0

	share0, err := c.gens[dealerIdx].DistKeyShare()
	require.NoError(t, err)

	prevHandler, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        suite,
		Longterm:     c.longterms[dealerIdx],
		OldNodes:     c.pubs,
		NewNodes:     newPubs,
		Share:        share0,
		Threshold:    threshold,
		OldThreshold: threshold,
	})
	require.NoError(t, err)
	_, err = prevHandler.Deals()
	require.NoError(t, err)

	vresp := &vss.Response{Index: verifierIdx, Status: vss.StatusComplaint}
	vresp.Signature, err = schnorr.Sign(suite, newLong[verifierIdx], vresp.Hash(suite))
	require.NoError(t, err)

	j, err := prevHandler.ProcessResponse(&dkg.Response{Index: dealerIdx, Response: vresp})
	require.NoError(t, err)
	require.NotNil(t, j)

	require.NoError(t, signResharingJustification(suite, c.longterms[dealerIdx], j))

	pbJ, err := types.ConvertToJustificationProto(j)
	require.NoError(t, err)

	// The dealer pubkey the CL looks up is the dealer's prev-round dkgPubKey.
	require.NoError(t, verifyJustificationLikeStoryClient(suite, pbJ, c.pubs[dealerIdx]),
		"kernel-signed justification must pass the story client's exact verification")

	// Negative control: a flipped signature byte must fail the same path.
	tampered, err := types.ConvertToJustificationProto(j)
	require.NoError(t, err)
	tampered.GetVssJustification().GetSignature()[0] ^= 0xFF
	require.Error(t, verifyJustificationLikeStoryClient(suite, tampered, c.pubs[dealerIdx]))
}

// TestSignResharingJustification_InitialPathUntouched confirms the initial-DKG
// path — where kyber already Schnorr-signs the justification — is not re-signed
// or overwritten, and the signature still verifies.
func TestSignResharingJustification_InitialPathUntouched(t *testing.T) {
	t.Parallel()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	const n, threshold = 3, 2

	long := make([]kyber.Scalar, n)
	pubs := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		long[i] = suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(long[i], nil)
	}

	gens := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		g, err := dkg.NewDistKeyGenerator(suite, long[i], pubs, threshold)
		require.NoError(t, err)
		gens[i] = g
	}

	const dealerIdx, verifierIdx = 0, 1

	deals, err := gens[dealerIdx].Deals()
	require.NoError(t, err)

	// Verifier processes the dealer's honest deal -> approval carrying the correct
	// sessionID and a valid signature; flip it to a complaint and re-sign so the
	// dealer's non-resharing path produces a kyber-SIGNED justification.
	resp, err := gens[verifierIdx].ProcessDeal(deals[verifierIdx])
	require.NoError(t, err)
	require.Equal(t, vss.StatusApproval, resp.Response.Status)

	resp.Response.Status = vss.StatusComplaint
	resp.Response.Signature, err = schnorr.Sign(suite, long[verifierIdx], resp.Response.Hash(suite))
	require.NoError(t, err)

	j, err := gens[dealerIdx].ProcessResponse(resp)
	require.NoError(t, err)
	require.NotNil(t, j)
	require.NotEmpty(t, j.Justification.Signature, "kyber must sign the initial-DKG justification")

	// The fix must be a no-op here: same signature bytes, still valid.
	before := append([]byte(nil), j.Justification.Signature...)
	require.NoError(t, signResharingJustification(suite, long[dealerIdx], j))
	assert.Equal(t, before, j.Justification.Signature, "initial-DKG signature must not be re-signed/overwritten")
	require.NoError(t, schnorr.Verify(suite, pubs[dealerIdx], j.Justification.Hash(suite), j.Justification.Signature))
}

// buildUnsignedResharingJustification constructs a resharing dealer whose key
// rotated out of the new committee (newPresent=false) and the crafted complaint
// pb.Response that drives kyber to emit an UNSIGNED justification — the exact
// shape applyResponses must sign. Mirrors the construction in
// TestSignResharingJustification_ResharingSignsAndVerifies but returns the
// pieces needed to drive applyResponses end to end.
func buildUnsignedResharingJustification(t *testing.T) (
	suite *edwards25519.SuiteEd25519,
	c *certifiedDKG,
	dealer *dkg.DistKeyGenerator,
	resp *pb.Response,
	dealerIdx, dealerCount, complainerCount int,
) {
	t.Helper()

	suite = edwards25519.NewBlakeSHA256Ed25519()

	const nOld, nNew, threshold = 3, 3, 2
	c = runCertifiedInitialDKG(t, nOld, threshold)

	// New committee uses fresh (rotated) keys, so every old dealer has
	// newPresent=false and routes responses through processResharingResponse.
	newLong := make([]kyber.Scalar, nNew)
	newPubs := make([]kyber.Point, nNew)
	for i := 0; i < nNew; i++ {
		newLong[i] = suite.Scalar().Pick(suite.RandomStream())
		newPubs[i] = suite.Point().Mul(newLong[i], nil)
	}

	dealerIdx = 0
	const verifierIdx = 0

	share, err := c.gens[dealerIdx].DistKeyShare()
	require.NoError(t, err)

	dealer, err = dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        suite,
		Longterm:     c.longterms[dealerIdx],
		OldNodes:     c.pubs,
		NewNodes:     newPubs,
		Share:        share,
		Threshold:    threshold,
		OldThreshold: threshold,
	})
	require.NoError(t, err)

	// Dealer emits its resharing deals, as in production, before handling responses.
	_, err = dealer.Deals()
	require.NoError(t, err)

	// Crafted StatusComplaint from new-committee verifier 0 against the dealer's own
	// deal: the dealer's fresh aggregator has no sessionID yet, so it only checks the
	// verifier's Schnorr signature — the cheapest way to emit an unsigned justification.
	vresp := &vss.Response{Index: verifierIdx, Status: vss.StatusComplaint}
	vresp.Signature, err = schnorr.Sign(suite, newLong[verifierIdx], vresp.Hash(suite))
	require.NoError(t, err)

	resp = types.ConvertToRespProto(&dkg.Response{Index: uint32(dealerIdx), Response: vresp})

	return suite, c, dealer, resp, dealerIdx, nOld, nNew
}

// newPlaintextDKGStore returns a real DKGStore backed by the plaintext sealer, so
// applyResponses' lazy LoadSealedEd25519Key wiring runs against real disk I/O.
func newPlaintextDKGStore(t *testing.T, suite *edwards25519.SuiteEd25519) *store.DKGStore {
	t.Helper()

	dir := t.TempDir()

	return store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)
}

// TestApplyResponses_ResharingJustificationSignedViaWiring drives applyResponses
// through the full signing path (ProcessResponse → lazy dealer-key load → sign →
// ConvertToJustificationProto) and asserts the forwarded justification carries a
// signature that verifies against the dealer's prev-round dkgPubKey — proving the
// wiring, not just the isolated signResharingJustification helper, works.
func TestApplyResponses_ResharingJustificationSignedViaWiring(t *testing.T) {
	t.Parallel()

	suite, c, dealer, resp, dealerIdx, dealerCount, complainerCount := buildUnsignedResharingJustification(t)

	const (
		cc          = "cc-apply-responses-signed"
		round       = uint32(5)
		dealerRound = uint32(4)
	)

	st := newPlaintextDKGStore(t, suite)

	// Seal the dealer's prev-round key under dealerRound so the lazy load succeeds.
	dealerBz, err := c.longterms[dealerIdx].MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, dealerRound, dealerBz))

	s := &DKGServer{Suite: suite, DKGStore: st}

	justs, processed, rejected, err := s.applyResponses(
		[]*dkg.DistKeyGenerator{dealer}, true, cc, round, dealerRound,
		dealerCount, complainerCount, []*pb.Response{resp},
	)
	require.NoError(t, err)

	require.Empty(t, rejected)
	require.Equal(t, 1, processed, "the processed response must be persisted")
	require.Len(t, justs, 1, "the signed justification must be forwarded")

	sig := justs[0].GetVssJustification().GetSignature()
	require.NotEmpty(t, sig, "the wiring must sign the resharing justification")

	// Verify exactly as the CL does: reconstruct, hash, verify against the
	// dealer's prev-round dkgPubKey.
	kyberJ, err := types.ConvertToJustification(justs[0])
	require.NoError(t, err)
	require.NoError(t, schnorr.Verify(suite, c.pubs[dealerIdx], kyberJ.Justification.Hash(suite), sig))
}

// TestApplyResponses_KeyLoadFailureDropsJustification asserts that when the dealer
// key is absent (LoadSealedEd25519Key errors), applyResponses DROPS the
// justification rather than forwarding an unsigned one the CL would reject — while
// still persisting the underlying response so kyber's state stays consistent.
func TestApplyResponses_KeyLoadFailureDropsJustification(t *testing.T) {
	t.Parallel()

	suite, _, dealer, resp, dealerIdx, dealerCount, complainerCount := buildUnsignedResharingJustification(t)

	const (
		cc          = "cc-apply-responses-drop"
		round       = uint32(5)
		dealerRound = uint32(4)
	)

	// Do NOT seal the dealer key under dealerRound, so the lazy load fails.
	st := newPlaintextDKGStore(t, suite)

	s := &DKGServer{Suite: suite, DKGStore: st}

	justs, processed, rejected, err := s.applyResponses(
		[]*dkg.DistKeyGenerator{dealer}, true, cc, round, dealerRound,
		dealerCount, complainerCount, []*pb.Response{resp},
	)
	require.NoError(t, err)

	require.Empty(t, justs, "an unsignable justification must be dropped, not forwarded")
	require.Empty(t, rejected, "a key-load failure is not a response rejection")
	require.Equal(t, 1, processed, "the response must still be persisted for state consistency")

	loaded, err := st.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded.Responses, 1)
	require.Equal(t, uint32(dealerIdx), loaded.Responses[0].Index)
}

// buildSignedInitialJustification runs an initial (non-resharing) DKG far enough
// to drive one dealer to emit a kyber-SIGNED justification for a crafted complaint,
// and returns the pieces needed to drive applyResponses through the idempotent
// re-emit path. Unlike the resharing-own-deal path (which re-generates on every
// call), the initial path stores the response in the verifier's aggregator, so a
// second ProcessResponse of the same response returns the idempotent
// "already existing response from same origin" error — exactly the retry scenario.
func buildSignedInitialJustification(t *testing.T) (
	suite *edwards25519.SuiteEd25519,
	pubs []kyber.Point,
	dealer *dkg.DistKeyGenerator,
	resp *pb.Response,
	dealerIdx, n int,
) {
	t.Helper()

	suite = edwards25519.NewBlakeSHA256Ed25519()

	const threshold = 2
	n = 3

	long := make([]kyber.Scalar, n)
	pubs = make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		long[i] = suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(long[i], nil)
	}

	gens := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		g, err := dkg.NewDistKeyGenerator(suite, long[i], pubs, threshold)
		require.NoError(t, err)
		gens[i] = g
	}

	dealerIdx = 0
	const verifierIdx = 1

	deals, err := gens[dealerIdx].Deals()
	require.NoError(t, err)

	// Verifier processes the dealer's honest deal -> approval with the correct
	// sessionID; flip to a complaint and re-sign so the dealer's initial path
	// produces a kyber-SIGNED justification.
	vresp, err := gens[verifierIdx].ProcessDeal(deals[verifierIdx])
	require.NoError(t, err)

	vresp.Response.Status = vss.StatusComplaint
	vresp.Response.Signature, err = schnorr.Sign(suite, long[verifierIdx], vresp.Response.Hash(suite))
	require.NoError(t, err)

	resp = types.ConvertToRespProto(vresp)

	return suite, pubs, gens[dealerIdx], resp, dealerIdx, n
}

// TestApplyResponses_ReEmitsEmittedJustificationOnRetry proves the fix: when a
// ProcessResponses batch is retried (client timed out), kyber's ProcessResponse
// is idempotent (returns j == nil) so the justification generated on the first
// call would be lost network-wide. The re-emit path must recover the persisted
// (signed) copy so the complaint can still be resolved. The re-emitted signature
// must be byte-identical to the original and still verify.
func TestApplyResponses_ReEmitsEmittedJustificationOnRetry(t *testing.T) {
	t.Parallel()

	suite, pubs, dealer, resp, dealerIdx, n := buildSignedInitialJustification(t)

	const (
		cc    = "cc-apply-responses-reemit"
		round = uint32(5)
	)

	st := newPlaintextDKGStore(t, suite)
	s := &DKGServer{Suite: suite, DKGStore: st}

	// First call: kyber generates and signs the justification (initial path), and
	// applyResponses persists it atomically.
	justs1, processed1, rejected1, err := s.applyResponses(
		[]*dkg.DistKeyGenerator{dealer}, false, cc, round, 0, n, n, []*pb.Response{resp},
	)
	require.NoError(t, err)
	require.Empty(t, rejected1)
	require.Equal(t, 1, processed1)
	require.Len(t, justs1, 1)

	sig1 := justs1[0].GetVssJustification().GetSignature()
	require.NotEmpty(t, sig1)

	loaded1, err := st.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded1.EmittedJustifications, 1, "the generated justification must be persisted")

	// Second call: same response batch + same generator. kyber is now idempotent
	// (already existing response from same origin), so the justification can only
	// come from the re-emit path.
	justs2, _, rejected2, err := s.applyResponses(
		[]*dkg.DistKeyGenerator{dealer}, false, cc, round, 0, n, n, []*pb.Response{resp},
	)
	require.NoError(t, err)
	require.Empty(t, rejected2, "an idempotent response must not be rejected")
	require.Len(t, justs2, 1, "the justification must be re-emitted on retry")

	loaded2, err := st.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded2.EmittedJustifications, 1, "no fresh justification is persisted on the idempotent retry")

	sig2 := justs2[0].GetVssJustification().GetSignature()
	require.Equal(t, sig1, sig2, "re-emitted signature must be byte-identical to the original")

	// The re-emitted signature must still verify against the dealer's dkgPubKey.
	kyberJ, err := types.ConvertToJustification(justs2[0])
	require.NoError(t, err)
	require.NoError(t, schnorr.Verify(suite, pubs[dealerIdx], kyberJ.Justification.Hash(suite), sig2))
}

// TestApplyResponses_SeparatesEmittedJustifications guards the replay invariant:
// a generated justification must land ONLY in EmittedJustifications, never in
// Justifications (peers'). replayMessages reads Justifications and re-applies them
// into the generator, so leaking an emitted justification there would double-apply.
func TestApplyResponses_SeparatesEmittedJustifications(t *testing.T) {
	t.Parallel()

	suite, c, dealer, resp, dealerIdx, dealerCount, complainerCount := buildUnsignedResharingJustification(t)

	const (
		cc          = "cc-apply-responses-separate"
		round       = uint32(5)
		dealerRound = uint32(4)
	)

	st := newPlaintextDKGStore(t, suite)

	dealerBz, err := c.longterms[dealerIdx].MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, dealerRound, dealerBz))

	s := &DKGServer{Suite: suite, DKGStore: st}

	_, processed, _, err := s.applyResponses(
		[]*dkg.DistKeyGenerator{dealer}, true, cc, round, dealerRound,
		dealerCount, complainerCount, []*pb.Response{resp},
	)
	require.NoError(t, err)
	require.Equal(t, 1, processed)

	loaded, err := st.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Empty(t, loaded.Justifications, "peers' Justifications must stay empty; replay must never pick up own justifications")
	require.Len(t, loaded.EmittedJustifications, 1, "the generated justification must land in EmittedJustifications")
	require.Len(t, loaded.Responses, 1, "the processed response must be persisted")

	// Sanity: the persisted own justification matches the response's (dealer,
	// complainer) key used by the re-emit lookup.
	require.Equal(t, uint32(dealerIdx), loaded.EmittedJustifications[0].Index)
}
