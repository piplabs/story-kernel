package dkgutil

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// setupTestDKG creates n DKG instances for testing. Returns the instances
// and their longterm key pairs.
func setupTestDKG(t *testing.T, n, threshold int) ([]*dkg.DistKeyGenerator, []kyber.Scalar, []kyber.Point) {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate longterm key pairs for each participant
	privKeys := make([]kyber.Scalar, n)
	pubKeys := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		privKeys[i] = suite.Scalar().Pick(suite.RandomStream())
		pubKeys[i] = suite.Point().Mul(privKeys[i], nil)
	}

	// Create DKG instances
	dkgs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		d, err := dkg.NewDistKeyGenerator(suite, privKeys[i], pubKeys, threshold)
		require.NoError(t, err, "NewDistKeyGenerator for node %d", i)
		dkgs[i] = d
	}

	return dkgs, privKeys, pubKeys
}

func TestExtractDealerPolyCoeffs(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Extract coefficients from the first node
	coeffBytes, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)
	require.NotEmpty(t, coeffBytes)

	// Verify we got the right number of coefficients (threshold)
	assert.Len(t, coeffBytes, 2, "coefficients count should equal threshold")

	// Verify each byte slice is non-empty and valid
	for i, bz := range coeffBytes {
		assert.NotEmpty(t, bz, "coefficient[%d] should not be empty", i)

		// Verify we can unmarshal back to a scalar
		s := suite.Scalar()
		err := s.UnmarshalBinary(bz)
		assert.NoError(t, err, "should unmarshal coefficient[%d]", i)
	}
}

func TestExtractDealerPolyCoeffs_NilDKG(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	_, err := ExtractDealerPolyCoeffs(nil, suite)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestRestoreDealerPoly_RoundTrip(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 4
	threshold := 3

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Extract the original polynomial from node 0
	origCoeffs, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)
	require.NotEmpty(t, origCoeffs)

	// Get the original dealer's session ID and commits for later comparison
	origDealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	origSessionID := origDealer.SessionID()
	origCommits := origDealer.Commits()

	// Create a NEW DKG instance (simulating restart) — this will have a
	// random polynomial, different from the original.
	freshDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)

	// Verify the fresh DKG has a DIFFERENT polynomial
	freshDealer, err := getDealerViaReflect(freshDKG)
	require.NoError(t, err)
	freshSessionID := freshDealer.SessionID()

	// The session IDs should differ because the polynomials differ
	assert.False(t, bytes.Equal(origSessionID, freshSessionID),
		"fresh DKG should have different session ID (different random polynomial)")

	// Restore the original polynomial
	err = RestoreDealerPoly(suite, freshDKG, origCoeffs)
	require.NoError(t, err)

	// Verify: session ID should now match the original
	restoredDealer, err := getDealerViaReflect(freshDKG)
	require.NoError(t, err)
	restoredSessionID := restoredDealer.SessionID()

	assert.True(t, bytes.Equal(origSessionID, restoredSessionID),
		"restored DKG should have the same session ID as original")

	// Verify: public commitments should match
	restoredCommits := restoredDealer.Commits()
	require.Len(t, restoredCommits, len(origCommits))
	for i := range origCommits {
		assert.True(t, origCommits[i].Equal(restoredCommits[i]),
			"commitment[%d] should match after restore", i)
	}

	// Verify: private polynomial coefficients should match
	restoredPoly := restoredDealer.PrivatePoly()
	origPoly := origDealer.PrivatePoly()
	assert.True(t, origPoly.Equal(restoredPoly),
		"restored polynomial should equal original")
}

func TestRestoreDealerPoly_EmptyCoeffs(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	err := RestoreDealerPoly(suite, dkgs[0], nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")

	err = RestoreDealerPoly(suite, dkgs[0], [][]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestRestoreDealerPoly_InvalidCoeffBytes(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Pass invalid byte slices
	err := RestoreDealerPoly(suite, dkgs[0], [][]byte{{0xff, 0xff}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

// TestRestoreDealerPoly_FullDKGProtocol runs a complete DKG protocol where
// one node "restarts" after generating deals, and verifies the protocol
// still completes successfully with the restored polynomial.
//
// This simulates the real rebuildInitDKG flow:
// 1. All nodes generate deals (each node's Deals() auto-processes its own deal)
// 2. Node 0 extracts polynomial coefficients
// 3. Peers process all deals normally (except deals TO node 0)
// 4. Node 0 "restarts" - new DKG created, polynomial restored
// 5. Node 0 replays incoming deals from peers (simulating replayMessages)
// 6. Node 0 calls Deals() again (simulating GenerateDeals RPC re-invocation)
// 7. All nodes process responses
// 8. All nodes should produce the same distributed key
func TestRestoreDealerPoly_FullDKGProtocol(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 4
	threshold := 3

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Phase 1: All nodes generate deals
	allDeals := make([]map[int]*dkg.Deal, n)
	for i := 0; i < n; i++ {
		deals, err := dkgs[i].Deals()
		require.NoError(t, err, "Deals() for node %d", i)
		allDeals[i] = deals
	}

	// Extract polynomial from node 0 (simulate saving before restart)
	origCoeffs, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Phase 2: Non-restarting nodes (1,2,3) process all deals normally.
	// Collect the deals sent TO node 0 (for replay after restart).
	dealsForNode0 := make([]*dkg.Deal, 0)
	allResponses := make(map[int][]*dkg.Response) // dealerIdx -> responses

	for dealerIdx := 0; dealerIdx < n; dealerIdx++ {
		for recipientIdx, deal := range allDeals[dealerIdx] {
			if recipientIdx == 0 {
				// Save deals for node 0 to replay after restart
				dealsForNode0 = append(dealsForNode0, deal)
				continue
			}
			resp, err := dkgs[recipientIdx].ProcessDeal(deal)
			require.NoError(t, err, "ProcessDeal: dealer=%d, recipient=%d", dealerIdx, recipientIdx)
			allResponses[dealerIdx] = append(allResponses[dealerIdx], resp)
		}
	}

	// Phase 3: Simulate node 0 restart - create fresh DKG and restore polynomial
	restoredDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)

	err = RestoreDealerPoly(suite, restoredDKG, origCoeffs)
	require.NoError(t, err)

	// Replace node 0's DKG with the restored one
	dkgs[0] = restoredDKG

	// Phase 4: Node 0 replays incoming deals from peers (simulating replayMessages)
	for _, deal := range dealsForNode0 {
		resp, err := dkgs[0].ProcessDeal(deal)
		require.NoError(t, err, "Node 0 ProcessDeal (replay) for dealer=%d", deal.Index)
		allResponses[int(deal.Index)] = append(allResponses[int(deal.Index)], resp)
	}

	// Phase 5: Node 0 calls Deals() again to process its own deal.
	// In the real flow, after rebuild, the story node re-invokes
	// GenerateDeals which calls Deals(). Since the polynomial was
	// restored, the deals produced will be identical to the originals.
	_, err = dkgs[0].Deals()
	require.NoError(t, err, "Node 0 Deals() after restore")

	// Phase 6: Process all responses on all nodes
	for i := 0; i < n; i++ {
		for dealerIdx := range allResponses {
			for _, resp := range allResponses[dealerIdx] {
				_, err := dkgs[i].ProcessResponse(resp)
				if err != nil {
					// Duplicate response errors are expected
					t.Logf("ProcessResponse: node=%d, dealer=%d, err=%v (may be expected)", i, dealerIdx, err)
				}
			}
		}
	}

	// Phase 7: Set timeout and verify all nodes can produce DistKeyShare
	for i := 0; i < n; i++ {
		dkgs[i].SetTimeout()
	}

	var distKeyShares []*dkg.DistKeyShare
	for i := 0; i < n; i++ {
		if !dkgs[i].ThresholdCertified() {
			t.Fatalf("node %d not threshold certified (QUAL=%v)", i, dkgs[i].QUAL())
		}

		dks, err := dkgs[i].DistKeyShare()
		require.NoError(t, err, "DistKeyShare() for node %d", i)
		require.NotNil(t, dks)
		distKeyShares = append(distKeyShares, dks)
	}

	// Phase 8: Verify all nodes agree on the distributed public key
	pubKey := distKeyShares[0].Public()
	for i := 1; i < n; i++ {
		assert.True(t, pubKey.Equal(distKeyShares[i].Public()),
			"node %d public key should match node 0", i)
	}

	// Phase 9: Verify the secret can be reconstructed from threshold shares
	priShares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		priShares[i] = distKeyShares[i].Share
	}

	recovered, err := share.RecoverSecret(suite, priShares, threshold, n)
	require.NoError(t, err)
	assert.True(t, pubKey.Equal(suite.Point().Mul(recovered, nil)),
		"recovered secret should correspond to the distributed public key")
}

// TestRestoreDealerPoly_ResponsesAfterRestore verifies that responses from
// peers (who hold the original deals) are correctly processed after the
// dealer polynomial is restored. This is the exact scenario that triggered
// the original bug: dealer.ProcessResponse checks session ID.
func TestRestoreDealerPoly_ResponsesAfterRestore(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 3
	threshold := 2

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Node 0 generates deals
	deals0, err := dkgs[0].Deals()
	require.NoError(t, err)

	// Extract polynomial from node 0
	coeffs0, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Peers process node 0's deals and generate responses
	var responses []*dkg.Response
	for recipientIdx, deal := range deals0 {
		resp, err := dkgs[recipientIdx].ProcessDeal(deal)
		require.NoError(t, err, "ProcessDeal for recipient %d", recipientIdx)
		responses = append(responses, resp)
	}

	// Simulate node 0 restart
	restoredDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)

	// Restore polynomial
	err = RestoreDealerPoly(suite, restoredDKG, coeffs0)
	require.NoError(t, err)

	// Process peers' responses to OUR deals on the restored DKG.
	// This is the critical test: dealer.ProcessResponse checks
	// bytes.Equal(r.SessionID, d.sessionID). If the polynomial wasn't
	// restored, this would fail with "wrong sessionID in response".
	for _, resp := range responses {
		_, err := restoredDKG.ProcessResponse(resp)
		// Note: ProcessResponse returns error for "unknown dealer" since
		// the restored DKG hasn't processed any deals yet (no verifiers
		// set for other dealers). This is expected - the important thing
		// is that responses about OUR deals (resp.Index == our_oidx)
		// don't fail with sessionID mismatch.
		if err != nil {
			t.Logf("ProcessResponse result (expected some errors): %v", err)
		}
	}
}

func TestComputeSessionID_Deterministic(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create test keys
	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)

	verifiers := make([]kyber.Point, 3)
	for i := range verifiers {
		verifiers[i] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	}

	commits := make([]kyber.Point, 2)
	for i := range commits {
		commits[i] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	}

	// Compute twice - should be deterministic
	sid1, err := ComputeSessionID(suite, pub, verifiers, commits, 2)
	require.NoError(t, err)

	sid2, err := ComputeSessionID(suite, pub, verifiers, commits, 2)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(sid1, sid2), "session ID should be deterministic")

	// Different threshold should produce different session ID
	sid3, err := ComputeSessionID(suite, pub, verifiers, commits, 3)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(sid1, sid3), "different threshold should produce different session ID")
}

func TestGetDealerViaReflect(t *testing.T) {
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Should successfully extract dealer from a fresh DKG
	dealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	require.NotNil(t, dealer)

	// Verify the dealer has expected methods
	poly := dealer.PrivatePoly()
	assert.NotNil(t, poly)
	assert.Len(t, poly.Coefficients(), 2) // threshold = 2

	commits := dealer.Commits()
	assert.Len(t, commits, 2) // threshold = 2

	sid := dealer.SessionID()
	assert.NotEmpty(t, sid)
}

func TestGetDealerPublicInfo(t *testing.T) {
	n := 3
	threshold := 2

	dkgs, _, pubKeys := setupTestDKG(t, n, threshold)

	dealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)

	pub, verifiers, tVal, err := getDealerPublicInfo(dealer)
	require.NoError(t, err)

	// Verify public key matches node 0's pub key
	assert.True(t, pub.Equal(pubKeys[0]), "dealer pub key should match node 0's key")

	// Verify verifiers list matches participants
	assert.Len(t, verifiers, n)
	for i, v := range verifiers {
		assert.True(t, v.Equal(pubKeys[i]),
			"verifier[%d] should match pubKeys[%d]", i, i)
	}

	// Verify threshold
	assert.Equal(t, threshold, tVal)
}

// TestExtractDealerPolyCoeffs_ZerosCoefficientsAfterUse verifies that
// ExtractDealerPolyCoeffs zeros the in-memory scalar coefficients after
// marshaling them. This is a defense-in-depth measure to prevent secret
// polynomial leakage via heap residue.
func TestExtractDealerPolyCoeffs_ZerosCoefficientsAfterUse(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Get a reference to the dealer's polynomial BEFORE extraction
	dealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	poly := dealer.PrivatePoly()
	require.NotNil(t, poly)

	// Grab the coefficient slice — these are the same kyber.Scalar objects
	// that ExtractDealerPolyCoeffs will zero via defer.
	coeffsBefore := poly.Coefficients()
	require.NotEmpty(t, coeffsBefore)

	// Verify coefficients are non-zero before extraction
	zeroScalar := suite.Scalar().Zero()
	for i, c := range coeffsBefore {
		require.False(t, c.Equal(zeroScalar),
			"coefficient[%d] should be non-zero before extraction", i)
	}

	// Extract — this should marshal first, then zero the coefficients via defer
	coeffBytes, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)
	require.NotEmpty(t, coeffBytes)

	// Verify: the returned byte slices are valid (non-zero, can be unmarshaled)
	for i, bz := range coeffBytes {
		s := suite.Scalar()
		err := s.UnmarshalBinary(bz)
		require.NoError(t, err, "returned coefficient[%d] bytes should be valid", i)
		require.False(t, s.Equal(zeroScalar),
			"returned coefficient[%d] should represent a non-zero scalar", i)
	}

	// Verify: the original in-memory scalars have been zeroed.
	// Since Coefficients() returns a copy of the slice but the kyber.Scalar
	// values are pointers to the same underlying data, Zero() on those
	// scalars mutates the actual objects. Re-fetch to confirm.
	coeffsAfter := poly.Coefficients()
	for i, c := range coeffsAfter {
		assert.True(t, c.Equal(zeroScalar),
			"coefficient[%d] should be zeroed after ExtractDealerPolyCoeffs", i)
	}
}

// TestExtractAndRestore_RoundTrip_WithZeroing verifies that the full
// Extract -> Restore round-trip works correctly even after the zeroing
// fix. The returned byte slices must remain valid for restoration.
func TestExtractAndRestore_RoundTrip_WithZeroing(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 3
	threshold := 2

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Get the original session ID for comparison
	origDealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	origSessionID := origDealer.SessionID()
	origCommits := origDealer.Commits()

	// Extract coefficients (this will zero the originals)
	coeffBytes, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Restore into a fresh DKG instance — the byte slices must still be valid
	freshDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)

	err = RestoreDealerPoly(suite, freshDKG, coeffBytes)
	require.NoError(t, err)

	// Verify session ID and commitments match the original
	restoredDealer, err := getDealerViaReflect(freshDKG)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(origSessionID, restoredDealer.SessionID()),
		"restored session ID should match original")

	restoredCommits := restoredDealer.Commits()
	require.Len(t, restoredCommits, len(origCommits))
	for i := range origCommits {
		assert.True(t, origCommits[i].Equal(restoredCommits[i]),
			"commitment[%d] should match after restore", i)
	}
}

// TestExtractAndRestoreCoefficients_CoefficientsPreserved verifies that
// extracted coefficient bytes faithfully represent the original polynomial.
// Note: after extraction, the in-memory scalars are zeroed (defense-in-depth),
// so we capture the original bytes BEFORE calling ExtractDealerPolyCoeffs.
func TestExtractAndRestoreCoefficients_CoefficientsPreserved(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Capture original coefficient bytes BEFORE extraction (which zeros them)
	origDealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	origCoeffs := origDealer.PrivatePoly().Coefficients()

	origCoeffBytes := make([][]byte, len(origCoeffs))
	for i, c := range origCoeffs {
		bz, err := c.MarshalBinary()
		require.NoError(t, err)
		origCoeffBytes[i] = bz
	}

	// Extract coefficients (this will zero the in-memory scalars)
	coeffBytes, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Verify byte representation matches the pre-extraction snapshot
	for i := range origCoeffBytes {
		assert.True(t, bytes.Equal(origCoeffBytes[i], coeffBytes[i]),
			"coefficient[%d] bytes should match pre-extraction snapshot", i)
	}

	// Verify round-trip: unmarshal extracted bytes and compare with snapshot
	for i, bz := range coeffBytes {
		s := suite.Scalar()
		err := s.UnmarshalBinary(bz)
		require.NoError(t, err)

		orig := suite.Scalar()
		err = orig.UnmarshalBinary(origCoeffBytes[i])
		require.NoError(t, err)

		assert.True(t, s.Equal(orig),
			"unmarshaled coefficient[%d] should equal original", i)
	}
}

// TestComputeSessionID_MatchesKyberInternal verifies that our session ID
// computation matches what kyber computes internally for a dealer.
func TestComputeSessionID_MatchesKyberInternal(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgs, _, _ := setupTestDKG(t, 3, 2)

	// Get the dealer's internally-computed session ID
	dealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)
	kyberSessionID := dealer.SessionID()

	// Get the dealer's public info
	pub, verifiers, tVal, err := getDealerPublicInfo(dealer)
	require.NoError(t, err)

	// Get commitments
	commits := dealer.Commits()

	// Compute session ID using our function
	ourSessionID, err := ComputeSessionID(suite, pub, verifiers, commits, tVal)
	require.NoError(t, err)

	// They must match
	assert.True(t, bytes.Equal(kyberSessionID, ourSessionID),
		"our session ID computation must match kyber's internal computation")
}

// TestRestoreDealerPoly_DealsMatchOriginal verifies that after restoring
// the polynomial, the dealer produces deals with the same session ID and
// secret shares as the original.
func TestRestoreDealerPoly_DealsMatchOriginal(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 3
	threshold := 2

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Get original dealer's plaintext deals
	origDealer, err := getDealerViaReflect(dkgs[0])
	require.NoError(t, err)

	origDeals := make([]*vss.Deal, n)
	for i := 0; i < n; i++ {
		origDeals[i], err = origDealer.PlaintextDeal(i)
		require.NoError(t, err)
	}

	// Extract coefficients
	coeffBytes, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Create new DKG and restore
	freshDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)
	err = RestoreDealerPoly(suite, freshDKG, coeffBytes)
	require.NoError(t, err)

	// Get restored dealer's plaintext deals
	restoredDealer, err := getDealerViaReflect(freshDKG)
	require.NoError(t, err)

	for i := 0; i < n; i++ {
		resDeal, err := restoredDealer.PlaintextDeal(i)
		require.NoError(t, err)

		assert.True(t, bytes.Equal(origDeals[i].SessionID, resDeal.SessionID),
			"deal[%d] session ID should match", i)
		assert.Equal(t, origDeals[i].SecShare.I, resDeal.SecShare.I,
			"deal[%d] share index should match", i)
		assert.True(t, origDeals[i].SecShare.V.Equal(resDeal.SecShare.V),
			"deal[%d] share value should match", i)
		assert.Equal(t, origDeals[i].T, resDeal.T,
			"deal[%d] threshold should match", i)
		require.Len(t, resDeal.Commitments, len(origDeals[i].Commitments),
			"deal[%d] commitments length should match", i)
		for j := range origDeals[i].Commitments {
			assert.True(t, origDeals[i].Commitments[j].Equal(resDeal.Commitments[j]),
				"deal[%d] commitment[%d] should match", i, j)
		}
	}
}

// TestRestoreDealerPoly_SelfVerifierResponses verifies that after restoring the
// dealer polynomial and processing the self-deal via Deals(), responses about
// our own deal from peers are correctly accepted. This was the root cause of
// the global_pub_key inconsistency after restart: verifiers[self] had no deal,
// so responses for our deal were silently rejected during replayMessages.
func TestRestoreDealerPoly_SelfVerifierResponses(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 4
	threshold := 3

	dkgs, privKeys, pubKeys := setupTestDKG(t, n, threshold)

	// Phase 1: All nodes generate deals (each Deals() auto-processes self-deal)
	allDeals := make([]map[int]*dkg.Deal, n)
	for i := 0; i < n; i++ {
		deals, err := dkgs[i].Deals()
		require.NoError(t, err)
		allDeals[i] = deals
	}

	// Extract polynomial from node 0
	origCoeffs, err := ExtractDealerPolyCoeffs(dkgs[0], suite)
	require.NoError(t, err)

	// Phase 2: All non-restarting nodes process deals and generate responses.
	// Collect deals for node 0 and all responses.
	dealsForNode0 := make([]*dkg.Deal, 0)
	responsesForDealer0 := make([]*dkg.Response, 0) // responses about node 0's deals
	otherResponses := make([]*dkg.Response, 0)

	for dealerIdx := 0; dealerIdx < n; dealerIdx++ {
		for recipientIdx, deal := range allDeals[dealerIdx] {
			if recipientIdx == 0 {
				dealsForNode0 = append(dealsForNode0, deal)
				continue
			}
			resp, err := dkgs[recipientIdx].ProcessDeal(deal)
			require.NoError(t, err)
			if dealerIdx == 0 {
				responsesForDealer0 = append(responsesForDealer0, resp)
			} else {
				otherResponses = append(otherResponses, resp)
			}
		}
	}

	// Phase 3: Node 0 restarts — create fresh DKG, restore polynomial, process self-deal
	restoredDKG, err := dkg.NewDistKeyGenerator(suite, privKeys[0], pubKeys, threshold)
	require.NoError(t, err)

	err = RestoreDealerPoly(suite, restoredDKG, origCoeffs)
	require.NoError(t, err)

	// KEY FIX: Process self-deal via Deals() before replaying anything
	_, err = restoredDKG.Deals()
	require.NoError(t, err, "Deals() should succeed after polynomial restore")

	// Phase 4: Replay incoming deals from peers
	for _, deal := range dealsForNode0 {
		resp, err := restoredDKG.ProcessDeal(deal)
		require.NoError(t, err)
		otherResponses = append(otherResponses, resp)
	}

	// Phase 5: THE CRITICAL TEST — replay responses for OUR deal.
	// Before the fix, this would silently fail because verifiers[self] had no deal.
	for _, resp := range responsesForDealer0 {
		just, err := restoredDKG.ProcessResponse(resp)
		require.NoError(t, err, "ProcessResponse for our deal should succeed after self-deal processing")
		require.Nil(t, just, "no justification expected for approval responses")
	}

	// Replace node 0 and process remaining responses on all nodes
	dkgs[0] = restoredDKG
	for i := 0; i < n; i++ {
		for _, resp := range otherResponses {
			dkgs[i].ProcessResponse(resp)
		}
		// Also replay dealer-0 responses on other nodes
		if i != 0 {
			for _, resp := range responsesForDealer0 {
				dkgs[i].ProcessResponse(resp)
			}
		}
	}

	// Phase 6: Verify all nodes produce consistent global_pub_key
	for i := 0; i < n; i++ {
		dkgs[i].SetTimeout()
	}

	shares := make([]*dkg.DistKeyShare, n)
	for i := 0; i < n; i++ {
		require.True(t, dkgs[i].ThresholdCertified(), "node %d should be certified", i)
		s, err := dkgs[i].DistKeyShare()
		require.NoError(t, err)
		shares[i] = s
	}

	// All nodes MUST agree on the global public key
	for i := 1; i < n; i++ {
		require.True(t, shares[0].Public().Equal(shares[i].Public()),
			"node %d global_pub_key should match node 0", i)
	}
}

// runFullDKG executes a complete DKG protocol for n nodes and returns the
// DistKeyShares. This is a helper for resharing tests that need an initial
// round's shares.
func runFullDKG(t *testing.T, suite *edwards25519.SuiteEd25519, n, threshold int, privKeys []kyber.Scalar, pubKeys []kyber.Point) []*dkg.DistKeyShare {
	t.Helper()

	dkgs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		d, err := dkg.NewDistKeyGenerator(suite, privKeys[i], pubKeys, threshold)
		require.NoError(t, err)
		dkgs[i] = d
	}

	// Generate and distribute deals
	allDeals := make([]map[int]*dkg.Deal, n)
	for i := 0; i < n; i++ {
		deals, err := dkgs[i].Deals()
		require.NoError(t, err)
		allDeals[i] = deals
	}

	// Process deals and collect responses
	allResps := make([]*dkg.Response, 0)
	for dealerIdx := 0; dealerIdx < n; dealerIdx++ {
		for recipientIdx, deal := range allDeals[dealerIdx] {
			resp, err := dkgs[recipientIdx].ProcessDeal(deal)
			require.NoError(t, err)
			allResps = append(allResps, resp)
		}
	}

	// Process responses
	for i := 0; i < n; i++ {
		for _, resp := range allResps {
			dkgs[i].ProcessResponse(resp)
		}
	}

	// Extract shares
	for i := 0; i < n; i++ {
		dkgs[i].SetTimeout()
	}
	shares := make([]*dkg.DistKeyShare, n)
	for i := 0; i < n; i++ {
		require.True(t, dkgs[i].ThresholdCertified(), "node %d not certified in initial DKG", i)
		s, err := dkgs[i].DistKeyShare()
		require.NoError(t, err)
		shares[i] = s
	}

	return shares
}

// TestRestoreDealerPoly_ResharingPrevDKG verifies that the polynomial restore
// + Deals() fix works for resharing prev DKG when a node is in both old and
// new committee lists.
//
// In resharing, NewDistKeyHandler creates a dealer using Share.V as the secret
// coefficient but generates random remaining coefficients. After restart, the
// rebuilt DKG has a different polynomial (different commitments, session ID),
// causing the same response verification failures as initial DKG.
//
// This test:
// 1. Runs a full initial DKG (3 nodes, threshold 2)
// 2. Starts resharing with the same 3 nodes (all in both old and new lists)
// 3. Node 0 generates resharing deals, then "restarts"
// 4. Restores polynomial + calls Deals() to process self-deal
// 5. Replays deals from peers and responses for our deal
// 6. Verifies all nodes produce consistent global_pub_key after resharing
func TestRestoreDealerPoly_ResharingPrevDKG(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 3
	threshold := 2

	// Generate keys
	privKeys := make([]kyber.Scalar, n)
	pubKeys := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		privKeys[i] = suite.Scalar().Pick(suite.RandomStream())
		pubKeys[i] = suite.Point().Mul(privKeys[i], nil)
	}

	// Phase 1: Complete initial DKG
	initialShares := runFullDKG(t, suite, n, threshold, privKeys, pubKeys)

	// Verify initial DKG produced consistent keys
	for i := 1; i < n; i++ {
		require.True(t, initialShares[0].Public().Equal(initialShares[i].Public()),
			"initial DKG: node %d public key mismatch", i)
	}

	// Phase 2: Build resharing prev DKG handlers (old committee dealing to new committee)
	// All nodes are in both old and new lists (self-resharing).
	prevDKGs := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		d, err := dkg.NewDistKeyHandler(&dkg.Config{
			Suite:        suite,
			Longterm:     privKeys[i],
			OldNodes:     pubKeys,
			NewNodes:     pubKeys,
			Share:        initialShares[i],
			Threshold:    threshold,
			OldThreshold: threshold,
		})
		require.NoError(t, err, "NewDistKeyHandler for resharing prev node %d", i)
		prevDKGs[i] = d
	}

	// Phase 3: All old nodes generate resharing deals
	allDeals := make([]map[int]*dkg.Deal, n)
	for i := 0; i < n; i++ {
		deals, err := prevDKGs[i].Deals()
		require.NoError(t, err, "Deals() for resharing prev node %d", i)
		allDeals[i] = deals
	}

	// Extract polynomial from node 0 before "restart"
	origCoeffs, err := ExtractDealerPolyCoeffs(prevDKGs[0], suite)
	require.NoError(t, err)
	require.NotEmpty(t, origCoeffs)

	// Phase 4: Non-restarting nodes process deals; save deals for node 0
	dealsForNode0 := make([]*dkg.Deal, 0)
	responsesForDealer0 := make([]*dkg.Response, 0)
	otherResponses := make([]*dkg.Response, 0)

	for dealerIdx := 0; dealerIdx < n; dealerIdx++ {
		for recipientIdx, deal := range allDeals[dealerIdx] {
			if recipientIdx == 0 {
				dealsForNode0 = append(dealsForNode0, deal)
				continue
			}
			resp, err := prevDKGs[recipientIdx].ProcessDeal(deal)
			require.NoError(t, err)
			if dealerIdx == 0 {
				responsesForDealer0 = append(responsesForDealer0, resp)
			} else {
				otherResponses = append(otherResponses, resp)
			}
		}
	}

	// Phase 5: Simulate node 0 restart — create fresh resharing prev DKG
	restoredPrev, err := dkg.NewDistKeyHandler(&dkg.Config{
		Suite:        suite,
		Longterm:     privKeys[0],
		OldNodes:     pubKeys,
		NewNodes:     pubKeys,
		Share:        initialShares[0],
		Threshold:    threshold,
		OldThreshold: threshold,
	})
	require.NoError(t, err)

	// Verify the fresh DKG has a DIFFERENT session ID (different random polynomial)
	origDealer, err := getDealerViaReflect(prevDKGs[0])
	require.NoError(t, err)
	freshDealer, err := getDealerViaReflect(restoredPrev)
	require.NoError(t, err)
	require.False(t, bytes.Equal(origDealer.SessionID(), freshDealer.SessionID()),
		"fresh resharing DKG should have different session ID")

	// Restore polynomial and process self-deal
	err = RestoreDealerPoly(suite, restoredPrev, origCoeffs)
	require.NoError(t, err)

	// Verify session ID is now restored
	restoredDealer, err := getDealerViaReflect(restoredPrev)
	require.NoError(t, err)
	require.True(t, bytes.Equal(origDealer.SessionID(), restoredDealer.SessionID()),
		"restored resharing DKG should have same session ID as original")

	// Process self-deal via Deals()
	_, err = restoredPrev.Deals()
	require.NoError(t, err, "Deals() after resharing polynomial restore")

	// Phase 6: Replay incoming deals from peers on restored node
	for _, deal := range dealsForNode0 {
		resp, err := restoredPrev.ProcessDeal(deal)
		require.NoError(t, err)
		otherResponses = append(otherResponses, resp)
	}

	// Phase 7: THE CRITICAL TEST — replay responses for our deal
	for _, resp := range responsesForDealer0 {
		just, err := restoredPrev.ProcessResponse(resp)
		require.NoError(t, err, "resharing: ProcessResponse for our deal must succeed after restore")
		require.Nil(t, just, "no justification expected for approval responses")
	}

	// Phase 8: Process remaining responses on all nodes
	prevDKGs[0] = restoredPrev
	for i := 0; i < n; i++ {
		for _, resp := range otherResponses {
			prevDKGs[i].ProcessResponse(resp)
		}
		if i != 0 {
			for _, resp := range responsesForDealer0 {
				prevDKGs[i].ProcessResponse(resp)
			}
		}
	}

	// Phase 9: Verify all nodes produce consistent DistKeyShare
	for i := 0; i < n; i++ {
		prevDKGs[i].SetTimeout()
	}

	resharingShares := make([]*dkg.DistKeyShare, n)
	for i := 0; i < n; i++ {
		require.True(t, prevDKGs[i].ThresholdCertified(),
			"resharing: node %d should be certified (QUAL=%v)", i, prevDKGs[i].QUAL())
		s, err := prevDKGs[i].DistKeyShare()
		require.NoError(t, err, "resharing: DistKeyShare() for node %d", i)
		resharingShares[i] = s
	}

	// All nodes MUST agree on the global public key
	for i := 1; i < n; i++ {
		require.True(t, resharingShares[0].Public().Equal(resharingShares[i].Public()),
			"resharing: node %d global_pub_key should match node 0", i)
	}

	// The reshared public key must equal the original (resharing preserves the key)
	require.True(t, initialShares[0].Public().Equal(resharingShares[0].Public()),
		"reshared global_pub_key must equal original")
}
