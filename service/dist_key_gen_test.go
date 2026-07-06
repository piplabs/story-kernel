package service

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// certifiedDKG bundles the artifacts of a completed initial DKG round in the
// shape the kernel persists them: dealsFor[i] holds the deals addressed to
// node i (a node's own deal is self-processed by kyber and never broadcast),
// and responses holds every broadcast response.
type certifiedDKG struct {
	longterms []kyber.Scalar
	pubs      []kyber.Point
	gens      []*dkg.DistKeyGenerator
	dealsFor  map[int][]dkg.Deal
	responses []dkg.Response
}

// storedResponsesFor returns the responses node self would have persisted:
// the CL filters out the node's own responses before the kernel stores them.
func (c *certifiedDKG) storedResponsesFor(self int) []dkg.Response {
	out := make([]dkg.Response, 0, len(c.responses))
	for _, r := range c.responses {
		if int(r.Response.Index) == self {
			continue
		}
		out = append(out, r)
	}

	return out
}

// runCertifiedInitialDKG runs a complete n-node initial DKG (all nodes present,
// every deal approved). Mirrors the kernel's construction in dist_key_gen.go.
func runCertifiedInitialDKG(t *testing.T, n, threshold int) *certifiedDKG {
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

	dealsFor := make(map[int][]dkg.Deal)
	allResponses := make([]dkg.Response, 0)
	for _, dealer := range gens {
		deals, err := dealer.Deals()
		require.NoError(t, err)

		for verifierIdx, deal := range deals {
			dealsFor[verifierIdx] = append(dealsFor[verifierIdx], *deal)
			resp, err := gens[verifierIdx].ProcessDeal(deal)
			require.NoError(t, err)
			allResponses = append(allResponses, *resp)
		}
	}

	for i := range allResponses {
		resp := allResponses[i]
		for verifierIdx, g := range gens {
			// Skip a verifier processing its own response (kyber rejects it).
			if int(resp.Response.Index) == verifierIdx {
				continue
			}
			_, err := g.ProcessResponse(&resp)
			require.NoError(t, err)
		}
	}

	for i, g := range gens {
		require.Truef(t, g.Certified(), "node %d must be certified", i)
	}

	return &certifiedDKG{
		longterms: longterms,
		pubs:      pubs,
		gens:      gens,
		dealsFor:  dealsFor,
		responses: allResponses,
	}
}

// newInitialReshareStore persists node self's view of a finished initial round
// (sealed longterm key, round state, sealed private coeffs) exactly as the
// kernel would have after GetInitDKG + GenerateDeals + the round's exchange.
func newInitialReshareStore(t *testing.T, c *certifiedDKG, self int, cc string, fromRound uint32, threshold int) *store.DKGStore {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()

	dir := t.TempDir()
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)

	selfBz, err := c.longterms[self].MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, fromRound, selfBz))

	require.NoError(t, st.SaveDKGState(&store.DKGState{
		Threshold: uint32(threshold),
		PubKeys:   c.pubs,
		Deals:     c.dealsFor[self],
		Responses: c.storedResponsesFor(self),
	}, cc, fromRound))

	coeffs, err := extractDealerPolyCoeffs(c.gens[self], suite)
	require.NoError(t, err)
	require.NoError(t, st.SetPrivateCoeffs(cc, fromRound, coeffs))

	return st
}

// TestGetResharingPrevDKG_FirstReshareAfterInitialDKG_RebuildPath is the
// regression test for issue #82: on the first reshare after an initial DKG, a
// node that persists the toRound state before generating its own deal (because
// a peer's deal was processed first) enters the rebuild branch of
// GetResharingPrevDKG. The fromRound instance must then be recovered via the
// initial-DKG path; the previous code unconditionally routed it through
// rebuildResharingNextDKG, which loaded the non-existent round-0 state and
// failed replay, invalidating the node ("no deal submitted").
//
// The warm-cache case is the observed incident (the initial round finalized in
// the same process); the cold-cache case is the same race after a kernel
// restart, exercising the full disk restore in rebuildInitDKG (sealed
// polynomial + self-deal + message replay).
func TestGetResharingPrevDKG_FirstReshareAfterInitialDKG_RebuildPath(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-initial-reshare"
		fromRound = uint32(3)
		toRound   = uint32(4)
		threshold = 2
	)

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}

	for _, tc := range []struct {
		name      string
		warmCache bool
	}{
		{name: "warm init cache", warmCache: true},
		{name: "cold cache restart recovery", warmCache: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := runCertifiedInitialDKG(t, 3, threshold)
			self := 0 // the node under test

			st := newInitialReshareStore(t, c, self, cc, fromRound, threshold)

			share, err := c.gens[self].DistKeyShare()
			require.NoError(t, err)

			// New committee uses fresh per-round keys (key rotation), so the
			// dealer is old-only (newPresent=false) as in production.
			nextPubs := []kyber.Point{point(41), point(42), point(43)}

			// Simulate losing the race: a peer's toRound deal was processed
			// first, so GetResharingNextDKG's build branch already persisted
			// both states. This flips HasDKGState(toRound) to true before our
			// own GenerateDeals runs.
			require.NoError(t, st.SetPrevDKGState(cc, fromRound, threshold, c.pubs, share.Commitments()))
			require.NoError(t, st.SetNextDKGState(cc, fromRound, toRound, threshold, nextPubs))

			s := &DKGServer{
				Suite:              suite,
				DKGStore:           st,
				InitDKGCache:       store.NewDKGCache(),
				ResharingPrevCache: store.NewResharingDKGCache(),
				ResharingNextCache: store.NewDKGCache(),
			}
			if tc.warmCache {
				// The initial round lives in InitDKGCache (never in
				// ResharingNextCache), exactly as after finalizing the initial
				// round in the same process.
				s.InitDKGCache.Set(fromRound, c.gens[self])
			}

			latest := &pb.DKGNetwork{Round: fromRound, Threshold: threshold, IsResharing: false}

			dkgInst, err := s.GetResharingPrevDKG(cc, toRound, threshold, nextPubs, latest)
			require.NoError(t, err, "rebuild branch must recover the initial round via the init path")
			require.NotNil(t, dkgInst)

			// The recovered instance must act as a dealer: an old-only member
			// returns a deal for every new-committee slot.
			deals, err := dkgInst.Deals()
			require.NoError(t, err)
			require.Len(t, deals, len(nextPubs), "dealer must produce a deal for every new-committee member")

			// Regression guard for the old routing: rebuilding the initial
			// round through the resharing-next path must now fail loudly
			// instead of silently building a malformed fresh-DKG handler from
			// the empty round-0 state.
			_, err = s.rebuildResharingNextDKG(cc, fromRound)
			require.ErrorContains(t, err, "missing or incomplete prev state")
		})
	}
}

// TestGetResharingPrevDKG_FirstReshareAfterInitialDKG_BuildPath covers the
// race winner: the node generates its own deal before any toRound state is
// persisted, taking the build branch (buildResharingPrevDKG) with the same
// initial-round routing and persisting both states for later rebuilds.
func TestGetResharingPrevDKG_FirstReshareAfterInitialDKG_BuildPath(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-initial-reshare-build"
		fromRound = uint32(3)
		toRound   = uint32(4)
		threshold = 2
	)

	c := runCertifiedInitialDKG(t, 3, threshold)
	self := 0

	st := newInitialReshareStore(t, c, self, cc, fromRound, threshold)

	share, err := c.gens[self].DistKeyShare()
	require.NoError(t, err)
	coeffsBz, err := MarshalPoints(share.Commitments())
	require.NoError(t, err)

	regs := make([]*pb.DKGRegistration, len(c.pubs))
	for i, p := range c.pubs {
		bz, err := p.MarshalBinary()
		require.NoError(t, err)
		regs[i] = &pb.DKGRegistration{Index: uint32(i + 1), Round: fromRound, DkgPubKey: bz}
	}

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}
	nextPubs := []kyber.Point{point(51), point(52), point(53)}

	latest := &pb.DKGNetwork{Round: fromRound, Threshold: threshold, IsResharing: false, PublicCoeffs: coeffsBz}

	s := &DKGServer{
		QueryClient:        &upgradeStubQC{latest: latest, regs: regs},
		Suite:              suite,
		DKGStore:           st,
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}
	s.InitDKGCache.Set(fromRound, c.gens[self])

	dkgInst, err := s.GetResharingPrevDKG(cc, toRound, threshold, nextPubs, latest)
	require.NoError(t, err)
	require.NotNil(t, dkgInst)

	deals, err := dkgInst.Deals()
	require.NoError(t, err)
	require.Len(t, deals, len(nextPubs))

	// The build branch must persist both states so a restart can rebuild.
	hasNext, err := st.HasDKGState(cc, toRound)
	require.NoError(t, err)
	require.True(t, hasNext, "build path must persist the toRound state")
}

// TestGetOrRebuildFromRoundDKG_ResharingRouting pins the isResharing=true
// branch: a resharing fromRound on a cold cache must be recovered through
// rebuildResharingNextDKG and come back as a receiver (no deals), never
// through the initial-DKG path.
func TestGetOrRebuildFromRoundDKG_ResharingRouting(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-chained-reshare"
		prevRound = uint32(3)
		fromRound = uint32(4)
		prevT     = uint32(2)
	)

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}

	dir := t.TempDir()
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)

	// This node is a member of the fromRound (new) committee.
	longterm := suite.Scalar().SetInt64(777)
	longtermBz, err := longterm.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, fromRound, longtermBz))

	prevPubs := []kyber.Point{point(11), point(12), point(13)}
	fromPubs := []kyber.Point{suite.Point().Mul(longterm, nil), point(21), point(22)}
	coeffs := []kyber.Point{point(101), point(102)} // len == prevT

	// fromRound was itself created by resharing from prevRound.
	require.NoError(t, st.SetPrevDKGState(cc, prevRound, prevT, prevPubs, coeffs))
	require.NoError(t, st.SetNextDKGState(cc, prevRound, fromRound, prevT, fromPubs))

	s := &DKGServer{
		Suite:              suite,
		DKGStore:           st,
		InitDKGCache:       store.NewDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}

	rebuilt, err := s.getOrRebuildFromRoundDKG(cc, fromRound, true)
	require.NoError(t, err)
	require.NotNil(t, rebuilt)

	// A resharing receiver holds no share yet: Deals() must be empty. (A
	// mis-routed fresh-DKG handler would be a dealer and return deals.)
	deals, err := rebuilt.Deals()
	require.NoError(t, err)
	require.Empty(t, deals, "rebuilt fromRound handler must be a resharing receiver")

	// The instance must be cached for subsequent callers.
	cached, ok := s.ResharingNextCache.Get(fromRound)
	require.True(t, ok)
	require.Same(t, rebuilt, cached)
}

// TestGetOrRebuildFromRoundDKG_ConcurrentWithGetInitDKG asserts the init-cache
// mutex domain is shared: a concurrent GetInitDKG and getOrRebuildFromRoundDKG
// for the same round must converge on a single cached instance (two
// differently-randomized instances would break session-ID verification for
// deals already broadcast from one of them). Run with -race.
func TestGetOrRebuildFromRoundDKG_ConcurrentWithGetInitDKG(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-concurrent"
		fromRound = uint32(3)
		threshold = 2
	)

	c := runCertifiedInitialDKG(t, 3, threshold)
	self := 0

	st := newInitialReshareStore(t, c, self, cc, fromRound, threshold)

	s := &DKGServer{
		Suite:        suite,
		DKGStore:     st,
		InitDKGCache: store.NewDKGCache(),
	}

	var (
		wg   sync.WaitGroup
		a, b *dkg.DistKeyGenerator
		aErr error
		bErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		a, aErr = s.GetInitDKG(cc, fromRound, threshold, c.pubs)
	}()
	go func() {
		defer wg.Done()
		b, bErr = s.getOrRebuildFromRoundDKG(cc, fromRound, false)
	}()
	wg.Wait()

	require.NoError(t, aErr)
	require.NoError(t, bErr)
	require.Same(t, a, b, "both paths must resolve to the same cached instance")
}

// TestRebuildResharingNextDKG_MissingPrevState covers the incomplete-prev-state
// guard: LoadDKGState returns an empty state (not an error) for a missing
// file, and kyber accepts a config without Share and PublicCoeffs by silently
// building a fresh-DKG handler with a new random polynomial. The rebuild must
// refuse instead. PublicCoeffs alone missing is equally fatal: Share is always
// nil on this path, so kyber's resharing detection rests solely on them.
func TestRebuildResharingNextDKG_MissingPrevState(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-empty-prev"
		prevRound = uint32(3)
		toRound   = uint32(4)
	)

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}

	for _, tc := range []struct {
		name      string
		fromRound uint32
		prep      func(t *testing.T, st *store.DKGStore)
	}{
		{
			// The round-0 state file does not exist at all.
			name:      "prev state missing entirely",
			fromRound: 0,
			prep:      func(*testing.T, *store.DKGStore) {},
		},
		{
			// PubKeys and Threshold present but PublicCoeffs absent — the
			// shape an initial round has right after GetInitDKG persists it,
			// or a prev round whose coeffs write was lost.
			name:      "prev state lacks public coeffs",
			fromRound: prevRound,
			prep: func(t *testing.T, st *store.DKGStore) {
				t.Helper()
				require.NoError(t, st.SaveDKGState(&store.DKGState{
					Threshold: 2,
					PubKeys:   []kyber.Point{point(11), point(12)},
				}, cc, prevRound))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			st := store.NewDKGStoreWithSealer(
				filepath.Join(dir, "keys"),
				filepath.Join(dir, "state"),
				suite,
				upgradePlaintextSealer{},
			)

			longterm := suite.Scalar().Pick(suite.RandomStream())
			longtermBz, err := longterm.MarshalBinary()
			require.NoError(t, err)
			require.NoError(t, st.SealAndStoreEd25519Key(cc, toRound, longtermBz))

			pubs := []kyber.Point{suite.Point().Mul(longterm, nil), point(2)}
			require.NoError(t, st.SetNextDKGState(cc, tc.fromRound, toRound, 2, pubs))

			tc.prep(t, st)

			s := &DKGServer{
				Suite:    suite,
				DKGStore: st,
			}

			_, err = s.rebuildResharingNextDKG(cc, toRound)
			require.ErrorContains(t, err, "missing or incomplete prev state")
		})
	}
}
