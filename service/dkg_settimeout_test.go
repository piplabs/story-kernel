package service

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"

	"github.com/piplabs/story-kernel/types"
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

// buildCertifiedGensWithPendingResponse builds an n-of-t DKG where every dealer
// deals and every verifier processes every deal, then broadcasts all responses to
// every generator EXCEPT it withholds exactly one response from gens[0]. gens[0]
// is therefore missing a single response (still certifiable under SetTimeout), and
// the withheld response is returned so a test can feed it "late" — mirroring an
// abandoned ProcessResponses retry — concurrently with FinalizeDKG's region.
func buildCertifiedGensWithPendingResponse(t *testing.T, n, threshold int) ([]*dkg.DistKeyGenerator, *dkg.Response) {
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

	var all []*dkg.Response
	for _, dealer := range gens {
		deals, err := dealer.Deals()
		require.NoError(t, err)
		for vidx, deal := range deals {
			resp, err := gens[vidx].ProcessDeal(deal)
			require.NoError(t, err)
			all = append(all, resp)
		}
	}

	// Deliver every response everywhere valid, withholding the first response
	// addressed to (but not emitted by) gens[0].
	var pending *dkg.Response
	for _, resp := range all {
		for vidx, g := range gens {
			// A verifier never processes its own response (kyber rejects it).
			if int(resp.Response.Index) == vidx {
				continue
			}
			if vidx == 0 && pending == nil {
				pending = resp
				continue
			}
			_, err := g.ProcessResponse(resp)
			require.NoError(t, err)
		}
	}
	require.NotNil(t, pending, "must withhold one response for gens[0]")

	return gens, pending
}

// TestFinalizeDKGRegion_SerializedWithLateResponse exercises the mutex-coverage
// fix: FinalizeDKG's SetTimeout+DistKeyShare region and a late/abandoned
// ProcessResponses both mutate the same cached generator. Guarded by
// getDKGMutationMu (as both RPCs now do), they serialize with no data race
// (run with -race) and the share still computes.
func TestFinalizeDKGRegion_SerializedWithLateResponse(t *testing.T) {
	t.Parallel()

	const (
		n         = 4
		threshold = 2
		round     = uint32(7)
	)

	gens, pending := buildCertifiedGensWithPendingResponse(t, n, threshold)
	g := gens[0]
	s := &DKGServer{}

	var (
		active  atomic.Int32
		overlap atomic.Bool
		wg      sync.WaitGroup
		share   *dkg.DistKeyShare
		finErr  error
	)
	// enter/leave flag whether two guarded regions were ever inside the per-round
	// mutex simultaneously; the sleep widens the window so a missing lock is caught
	// deterministically (not only under -race).
	enter := func() {
		if active.Add(1) > 1 {
			overlap.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
	}
	leave := func() { active.Add(-1) }

	wg.Add(2)

	// FinalizeDKG's guarded region.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		g.SetTimeout()
		share, finErr = g.DistKeyShare()
	}()

	// A late/abandoned ProcessResponses retry on the same instance; kyber may
	// accept or reject it depending on interleaving, but it must never run
	// concurrently with the finalize region.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		_, _ = g.ProcessResponse(pending)
	}()

	wg.Wait()

	require.False(t, overlap.Load(),
		"FinalizeDKG and ProcessResponses regions must not overlap under the per-round mutex")
	require.NoError(t, finErr)
	require.NotNil(t, share)
	require.NotNil(t, share.PriShare())
}

// TestGenerateDealsRegion_SerializedWithProcessDeal exercises the fix on the
// dealing side: GenerateDeals' guarded region (Deals + coeff extraction) and
// ProcessDeals' ProcessDeal both mutate the same cached generator. Under
// getDKGMutationMu they serialize cleanly (run with -race).
func TestGenerateDealsRegion_SerializedWithProcessDeal(t *testing.T) {
	t.Parallel()

	const (
		n         = 3
		threshold = 2
		round     = uint32(9)
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	const self = 0
	g := gens[self]
	incoming := dealsAddressedTo(t, gens, self)
	s := &DKGServer{Suite: suite}

	var (
		active  atomic.Int32
		overlap atomic.Bool
		wg      sync.WaitGroup
		gerr    error
		coeffs  [][]byte
	)
	enter := func() {
		if active.Add(1) > 1 {
			overlap.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
	}
	leave := func() { active.Add(-1) }

	wg.Add(2)

	// GenerateDeals' guarded region.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		_, gerr = g.Deals()
		if gerr == nil {
			coeffs, _ = extractDealerPolyCoeffs(g, s.Suite)
		}
	}()

	// ProcessDeals' guarded region on the same instance.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		for _, pd := range incoming {
			_, _ = g.ProcessDeal(types.ConvertToDeal(pd))
		}
	}()

	wg.Wait()

	require.False(t, overlap.Load(),
		"GenerateDeals and ProcessDeals regions must not overlap under the per-round mutex")
	require.NoError(t, gerr)
	require.NotEmpty(t, coeffs)
}

// buildFullyCertifiedGensWithReplayResponse builds an n-of-t DKG where every deal
// and every response is delivered everywhere, so gens[0] is ThresholdCertified and
// DistKeyShare() succeeds with no SetTimeout — matching the fromRound generator the
// resharing-prev path reads via existing.DistKeyShare() in loadFromRoundShare. It
// also returns one already-delivered response so a test can replay it "late"
// (idempotent to kyber, but still mutates aggregator state) concurrently with the read.
func buildFullyCertifiedGensWithReplayResponse(t *testing.T, n, threshold int) ([]*dkg.DistKeyGenerator, *dkg.Response) {
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

	var all []*dkg.Response
	for _, dealer := range gens {
		deals, err := dealer.Deals()
		require.NoError(t, err)
		for vidx, deal := range deals {
			resp, err := gens[vidx].ProcessDeal(deal)
			require.NoError(t, err)
			all = append(all, resp)
		}
	}

	// Deliver every response to every other generator so all are certified.
	var replay *dkg.Response
	for _, resp := range all {
		for vidx, g := range gens {
			if int(resp.Response.Index) == vidx {
				continue
			}
			_, err := g.ProcessResponse(resp)
			require.NoError(t, err)
			if replay == nil && vidx == 0 {
				replay = resp
			}
		}
	}
	require.NotNil(t, replay, "must capture one response addressed to gens[0] for replay")

	return gens, replay
}

// TestResharingDistKeyShareRead_SerializedWithLateResponse exercises the mutex-coverage
// fix on the resharing-setup path: loadFromRoundShare's live-recompute fallback reads
// the fromRound generator via existing.DistKeyShare() (which reads aggregator state
// through ThresholdCertified), while a late/abandoned ProcessResponses on that same
// shared fromRound instance mutates it. Both now take getDKGMutationMu(fromRound), so
// they serialize with no data race (run with -race) and the share still computes.
func TestResharingDistKeyShareRead_SerializedWithLateResponse(t *testing.T) {
	t.Parallel()

	const (
		n         = 4
		threshold = 2
		fromRound = uint32(11)
	)

	gens, replay := buildFullyCertifiedGensWithReplayResponse(t, n, threshold)
	g := gens[0]
	s := &DKGServer{}

	var (
		active  atomic.Int32
		overlap atomic.Bool
		wg      sync.WaitGroup
		share   *dkg.DistKeyShare
		readErr error
	)
	enter := func() {
		if active.Add(1) > 1 {
			overlap.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
	}
	leave := func() { active.Add(-1) }

	wg.Add(2)

	// Resharing from-round read region: exactly what loadFromRoundShare's fallback now guards.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(fromRound)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		share, readErr = g.DistKeyShare()
	}()

	// A late/abandoned ProcessResponses retry on the same fromRound instance.
	go func() {
		defer wg.Done()
		mu := s.getDKGMutationMu(fromRound)
		mu.Lock()
		defer mu.Unlock()
		enter()
		defer leave()
		_, _ = g.ProcessResponse(replay)
	}()

	wg.Wait()

	require.False(t, overlap.Load(),
		"resharing DistKeyShare read and ProcessResponses must not overlap under the per-round mutex")
	require.NoError(t, readErr)
	require.NotNil(t, share)
	require.NotNil(t, share.PriShare())
}
