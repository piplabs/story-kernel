package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// TestIsAlreadyProcessedErr_AgainstRealKyber drives a small live DKG with
// real kyber DistKeyGenerators and replays the same artifact twice to force
// kyber's idempotent-error paths. It asserts that isAlreadyProcessedErr
// classifies each real error correctly.
//
// Why this exists: TestIsAlreadyProcessedErr (in dkg_process_deals_test.go)
// pins the *literal* strings the matcher accepts. That catches matcher drift
// but NOT kyber drift — if a future kyber bump rewords any of these errors,
// the unit test still passes while production silently misclassifies real
// idempotent re-submissions as `rejected_*`. This test fails CI on kyber
// drift. Re-run after every go.dedis.ch/kyber bump.
//
// Justification idempotent path is intentionally omitted here: triggering
// it requires fabricating a complaint and processing the resulting
// justification twice, which adds a lot of fragile setup for marginal
// extra coverage. The literal-string assertion in TestIsAlreadyProcessedErr
// already pins that wording (`"vss: justification received for an
// approval"`). If kyber renames it, that test fails first.
func TestIsAlreadyProcessedErr_AgainstRealKyber(t *testing.T) {
	t.Parallel()

	const (
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Generate longterm key pairs and the corresponding public-key list.
	longterms := make([]kyber.Scalar, n)
	pubs := make([]kyber.Point, n)
	for i := range n {
		longterms[i] = suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(longterms[i], nil)
	}

	// One DistKeyGenerator per party.
	gens := make([]*dkg.DistKeyGenerator, n)
	for i := range n {
		g, err := dkg.NewDistKeyGenerator(suite, longterms[i], pubs, threshold)
		require.NoErrorf(t, err, "NewDistKeyGenerator party %d", i)
		gens[i] = g
	}

	// Party 0 issues deals for every other party.
	deals, err := gens[0].Deals()
	require.NoError(t, err)
	require.NotEmpty(t, deals)

	t.Run("deal-double-submit-yields-already-processed", func(t *testing.T) {
		t.Parallel()

		// Pick deal addressed to party 1.
		dealForP1, ok := deals[1]
		require.True(t, ok, "expected a deal for party 1")

		// Use a fresh generator for party 1 so this subtest does not race
		// with the response path below.
		g1, err := dkg.NewDistKeyGenerator(suite, longterms[1], pubs, threshold)
		require.NoError(t, err)

		// First ProcessDeal must succeed.
		_, err = g1.ProcessDeal(dealForP1)
		require.NoError(t, err)

		// Second ProcessDeal triggers kyber's
		//   var errDealAlreadyProcessed = errors.New("vss: verifier already received a deal")
		// (share/vss/pedersen/vss.go:552).
		_, err = g1.ProcessDeal(dealForP1)
		require.Error(t, err, "second ProcessDeal must fail")
		require.True(t, isAlreadyProcessedErr(err),
			"isAlreadyProcessedErr must classify kyber's deal-already-processed error: %v", err)
	})

	t.Run("response-double-submit-yields-already-existing", func(t *testing.T) {
		t.Parallel()

		// Build a fresh dealer (party 0) so the response-side state is
		// independent of the deal subtest.
		dealer, err := dkg.NewDistKeyGenerator(suite, longterms[0], pubs, threshold)
		require.NoError(t, err)
		dealerDeals, err := dealer.Deals()
		require.NoError(t, err)

		// Party 1 produces an approval response to party 0's deal.
		responder, err := dkg.NewDistKeyGenerator(suite, longterms[1], pubs, threshold)
		require.NoError(t, err)
		resp, err := responder.ProcessDeal(dealerDeals[1])
		require.NoError(t, err)

		// Dealer applies the response once — must succeed.
		_, err = dealer.ProcessResponse(resp)
		require.NoError(t, err)

		// Second ProcessResponse triggers kyber's
		//   errors.New("vss: already existing response from same origin")
		// (share/vss/pedersen/vss.go:656).
		_, err = dealer.ProcessResponse(resp)
		require.Error(t, err, "second ProcessResponse must fail")
		require.True(t, isAlreadyProcessedErr(err),
			"isAlreadyProcessedErr must classify kyber's response-already-existing error: %v", err)
	})
}
