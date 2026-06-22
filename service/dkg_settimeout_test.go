package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// buildDKGWithOneAbsentVerifier constructs an n-of-t Pedersen DKG, exchanges all
// deals, and processes responses from every verifier except one (absentIdx),
// which never responds. The returned generators model the exact #77 condition:
// a single verifier is missing from every dealer's response map.
//
// It mirrors the kernel's construction in dist_key_gen.go: the same Ed25519
// suite (NewBlakeSHA256Ed25519) and dkg.NewDistKeyGenerator. The returned slice
// excludes the absent node so callers operate only on participants that did
// respond, which is what the kernel does at finalization time.
func buildDKGWithOneAbsentVerifier(t *testing.T, n, threshold, absentIdx int) []*dkg.DistKeyGenerator {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	longterms := make([]kyber.Scalar, n)
	pubs := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		longterms[i] = suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(longterms[i], nil)
	}

	gens := make([]*dkg.DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		g, err := dkg.NewDistKeyGenerator(suite, longterms[i], pubs, threshold)
		require.NoError(t, err)
		gens[i] = g
	}

	// Every dealer produces its deals and every present verifier processes them,
	// generating a response. The absent verifier neither processes deals nor
	// emits responses.
	allResponses := make([]*dkg.Response, 0)
	for dealerIdx, dealer := range gens {
		deals, err := dealer.Deals()
		require.NoError(t, err)

		for verifierIdx, deal := range deals {
			if verifierIdx == absentIdx {
				// Absent verifier drops the deal; it never produces a response.
				continue
			}
			resp, err := gens[verifierIdx].ProcessDeal(deal)
			require.NoError(t, err)
			require.Equal(t, uint32(dealerIdx), resp.Index)
			allResponses = append(allResponses, resp)
		}
	}

	// Broadcast every response to every present verifier, excluding the absent one.
	for _, resp := range allResponses {
		for verifierIdx, g := range gens {
			if verifierIdx == absentIdx {
				continue
			}
			// Skip a verifier processing its own response (kyber rejects it).
			if int(resp.Response.Index) == verifierIdx {
				continue
			}
			_, err := g.ProcessResponse(resp)
			require.NoError(t, err)
		}
	}

	// Return only the present generators, in order.
	present := make([]*dkg.DistKeyGenerator, 0, n-1)
	for i, g := range gens {
		if i == absentIdx {
			continue
		}
		present = append(present, g)
	}
	return present
}

// TestDistKeyShare_AbsentVerifier_WithoutTimeout pins the broken behavior from
// #77: without SetTimeout, DealCertified takes the strict branch (requiring zero
// absent verifier responses), so no deal certifies, the threshold is not met,
// and DistKeyShare fails with "not certified".
func TestDistKeyShare_AbsentVerifier_WithoutTimeout(t *testing.T) {
	t.Parallel()

	const (
		n         = 4
		threshold = 2
		absent    = 3
	)

	present := buildDKGWithOneAbsentVerifier(t, n, threshold, absent)

	for i, g := range present {
		assert.False(t, g.ThresholdCertified(),
			"generator %d: must not be threshold-certified without timeout", i)

		// QUAL fails to reach the threshold because the strict branch rejects
		// every deal that is missing the absent verifier's response.
		assert.Less(t, len(g.QUAL()), threshold,
			"generator %d: QUAL must not reach the threshold without timeout", i)

		_, err := g.DistKeyShare()
		require.Error(t, err, "generator %d: DistKeyShare must fail without timeout", i)
		assert.Contains(t, err.Error(), "not certified")
	}
}

// TestDistKeyShare_AbsentVerifier_WithTimeout verifies the #77 fix: after
// SetTimeout, DealCertified tolerates up to n-t absent responses, so the
// present dealers certify, QUAL reaches at least the threshold, and
// DistKeyShare succeeds on every present generator.
func TestDistKeyShare_AbsentVerifier_WithTimeout(t *testing.T) {
	t.Parallel()

	const (
		n         = 4
		threshold = 2
		absent    = 3
	)

	present := buildDKGWithOneAbsentVerifier(t, n, threshold, absent)

	for _, g := range present {
		g.SetTimeout()
	}

	for i, g := range present {
		qual := g.QUAL()
		assert.GreaterOrEqual(t, len(qual), threshold,
			"generator %d: QUAL must reach the threshold with timeout", i)

		share, err := g.DistKeyShare()
		require.NoError(t, err, "generator %d: DistKeyShare must succeed with timeout", i)
		require.NotNil(t, share)
		require.NotNil(t, share.PriShare())
	}

	// All present generators must agree on the same global public key.
	want, err := present[0].DistKeyShare()
	require.NoError(t, err)
	for i := 1; i < len(present); i++ {
		got, err := present[i].DistKeyShare()
		require.NoError(t, err)
		assert.True(t, want.Public().Equal(got.Public()),
			"generator %d: global public key must match generator 0", i)
	}
}
