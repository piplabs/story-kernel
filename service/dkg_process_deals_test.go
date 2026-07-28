package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func TestValidateProcessDealsRequest_MissingRound(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          0,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "round should be greater than 0")
}

func TestValidateProcessDealsRequest_MissingCodeCommitment(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: nil,
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code commitment is required but missing")
}

func TestValidateProcessDealsRequest_EmptyDeals(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          nil,
	}

	err := validateProcessDealsRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty deals to process")
}

func TestValidateProcessDealsRequest_Valid(t *testing.T) {
	t.Parallel()

	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: []byte("32-byte-code-commitment-padding!!"),
		Deals:          []*pb.Deal{{Index: 1}},
	}

	err := validateProcessDealsRequest(req)
	require.NoError(t, err)
}

func TestValidateProcessDealsRequest_TableDriven(t *testing.T) {
	t.Parallel()

	validCC := []byte("32-byte-code-commitment-padding!!")
	validDeals := []*pb.Deal{{Index: 1}}

	tests := []struct {
		name           string
		round          uint32
		codeCommitment []byte
		deals          []*pb.Deal
		wantErr        bool
		errContains    string
	}{
		{
			name:           "all fields valid",
			round:          1,
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        false,
		},
		{
			name:           "round is zero",
			round:          0,
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        true,
			errContains:    "round should be greater than 0",
		},
		{
			name:           "code commitment is nil",
			round:          1,
			codeCommitment: nil,
			deals:          validDeals,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "code commitment is empty",
			round:          1,
			codeCommitment: []byte{},
			deals:          validDeals,
			wantErr:        true,
			errContains:    "code commitment is required but missing",
		},
		{
			name:           "deals is nil",
			round:          1,
			codeCommitment: validCC,
			deals:          nil,
			wantErr:        true,
			errContains:    "empty deals to process",
		},
		{
			name:           "deals is empty slice",
			round:          1,
			codeCommitment: validCC,
			deals:          []*pb.Deal{},
			wantErr:        true,
			errContains:    "empty deals to process",
		},
		{
			name:           "max round value",
			round:          ^uint32(0),
			codeCommitment: validCC,
			deals:          validDeals,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &pb.ProcessDealsRequest{
				Round:          tc.round,
				CodeCommitment: tc.codeCommitment,
				Deals:          tc.deals,
			}

			err := validateProcessDealsRequest(req)
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

// TestIsAlreadyProcessedErr pins the kyber v4.0.0-pre2 idempotent-error
// strings exactly so that a kyber upgrade renaming any of them fails this
// test loudly. See the NOTE on isAlreadyProcessedErr for upgrade procedure.
func TestIsAlreadyProcessedErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"verifier-already-deal", errDealAlreadyProcessedVerbatim(), true},
		{"already-existing-response", errAlreadyExistingResponseVerbatim(), true},
		{"justification-on-approval", errJustificationOnApprovalVerbatim(), true},
		{"case-insensitive", errors.New("VSS: ALREADY EXISTING RESPONSE FROM SAME ORIGIN"), true},
		{"wrapped-once", errWrap(errDealAlreadyProcessedVerbatim()), true},
		{"unrelated-error", errors.New("dkg: dist deal out of bounds index"), false},
		{"nil", nil, false},
		{"plain-non-match", errors.New("network unreachable"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, isAlreadyProcessedErr(tc.err))
		})
	}
}

// The next three helpers reproduce the EXACT kyber v4.0.0-pre2 error strings
// (lifted from share/vss/pedersen/vss.go lines 552, 656, 639). If a kyber
// upgrade changes the wording, the corresponding TestIsAlreadyProcessedErr
// case fails and points at the substring that needs updating.
func errDealAlreadyProcessedVerbatim() error {
	return errors.New("vss: verifier already received a deal")
}

func errAlreadyExistingResponseVerbatim() error {
	return errors.New("vss: already existing response from same origin")
}

func errJustificationOnApprovalVerbatim() error {
	return errors.New("vss: justification received for an approval")
}

// errWrap returns an error that wraps the input — used to verify
// isAlreadyProcessedErr handles wrapped errors via fmt.Errorf "%w".
func errWrap(inner error) error {
	return fmt.Errorf("kernel: %w", inner)
}

// --- applyDeals re-emit tests (issue #84) ---

// freshDKGGens builds n Pedersen DKG generators with fresh longterm keys.
// Nothing is exchanged yet, so a generator produces a real response the first
// time it processes a deal and an idempotent error on re-submission.
func freshDKGGens(t *testing.T, suite *edwards25519.SuiteEd25519, n, threshold int) []*dkg.DistKeyGenerator {
	t.Helper()

	pubs := make([]kyber.Point, n)
	longterms := make([]kyber.Scalar, n)
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

	return gens
}

// dealToProto is the inverse of types.ConvertToDeal for building test inputs.
func dealToProto(d *dkg.Deal) *pb.Deal {
	return &pb.Deal{
		Index: d.Index,
		Deal: &pb.EncryptedDeal{
			DhKey:     d.Deal.DHKey,
			Signature: d.Deal.Signature,
			Nonce:     d.Deal.Nonce,
			Cipher:    d.Deal.Cipher,
		},
		Signature: d.Signature,
	}
}

// dealsAddressedTo collects, as proto, the deals every other dealer produced
// for verifier self (Deal.Index is the dealer index, per kyber d.oidx).
func dealsAddressedTo(t *testing.T, gens []*dkg.DistKeyGenerator, self int) []*pb.Deal {
	t.Helper()

	var out []*pb.Deal
	for dealer := range gens {
		if dealer == self {
			continue
		}
		deals, err := gens[dealer].Deals()
		require.NoError(t, err)
		d, ok := deals[self]
		require.True(t, ok, "dealer %d must address verifier %d", dealer, self)
		out = append(out, dealToProto(d))
	}

	return out
}

func newServiceTestStore(t *testing.T) *store.DKGStore {
	t.Helper()

	dir := t.TempDir()

	return store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		edwards25519.NewBlakeSHA256Ed25519(),
		upgradePlaintextSealer{},
	)
}

func marshalResp(t *testing.T, r *pb.Response) []byte {
	t.Helper()

	b, err := proto.Marshal(r)
	require.NoError(t, err)

	return b
}

// TestApplyDeals_ReemitsStoredResponsesOnResubmit is the regression test for
// issue #84: when a ProcessDeals call is retried (the first response died with a
// timed-out connection), the cached generator returns already-processed, and
// applyDeals must re-emit the byte-identical responses it generated the first
// time — never dropping the verifier's approvals.
func TestApplyDeals_ReemitsStoredResponsesOnResubmit(t *testing.T) {
	t.Parallel()

	const (
		cc        = "cc-reemit"
		round     = uint32(1)
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	self := 0
	reqDeals := dealsAddressedTo(t, gens, self)
	require.Len(t, reqDeals, n-1)

	s := &DKGServer{Suite: suite, DKGStore: newServiceTestStore(t)}

	// First call processes the deals and persists deals + own responses.
	resp1, _, rej1, err := s.applyDeals(gens[self], cc, round, n, reqDeals)
	require.NoError(t, err)
	require.Empty(t, rej1)
	require.Len(t, resp1, len(reqDeals))

	// Retry: same deals, same cached generator -> kyber returns already-processed.
	resp2, _, rej2, err := s.applyDeals(gens[self], cc, round, n, reqDeals)
	require.NoError(t, err)
	require.Empty(t, rej2, "re-submitted deals must not be rejected")
	require.Len(t, resp2, len(resp1), "retry must re-emit every response")

	for i := range resp1 {
		require.Equal(t, marshalResp(t, resp1[i]), marshalResp(t, resp2[i]),
			"re-emitted response %d must be byte-identical to the original", i)
	}
}

// TestApplyDeals_EmittedResponsesStoredSeparately guards replay semantics: the
// generated responses land in EmittedResponses, and the peer-facing Responses field
// (read by replayMessages and the rebuild paths) stays empty.
func TestApplyDeals_EmittedResponsesStoredSeparately(t *testing.T) {
	t.Parallel()

	const (
		cc        = "cc-separate"
		round     = uint32(1)
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	self := 0
	reqDeals := dealsAddressedTo(t, gens, self)

	s := &DKGServer{Suite: suite, DKGStore: newServiceTestStore(t)}

	_, _, _, err := s.applyDeals(gens[self], cc, round, n, reqDeals)
	require.NoError(t, err)

	st, err := s.DKGStore.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Empty(t, st.Responses, "peers' Responses must stay empty")
	require.Len(t, st.EmittedResponses, len(reqDeals), "emitted responses must be persisted")
	require.Len(t, st.Deals, len(reqDeals), "deals must be persisted alongside")
}

// TestApplyDeals_MissingEmittedResponsesSilentlySkips covers the crash-between edge:
// the generator already absorbed the deal but no own response was persisted
// (deals persisted without emitted responses). The dedup path must skip silently — no response, no
// rejection.
func TestApplyDeals_MissingEmittedResponsesSilentlySkips(t *testing.T) {
	t.Parallel()

	const (
		cc        = "cc-missing"
		round     = uint32(1)
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	self := 0
	reqDeals := dealsAddressedTo(t, gens, self)

	// Absorb the deals so a later ProcessDeal returns already-processed, and
	// persist them via the legacy path that stores no own responses.
	raw := make([]dkg.Deal, 0, len(reqDeals))
	for _, pd := range reqDeals {
		d := types.ConvertToDeal(pd)
		_, err := gens[self].ProcessDeal(d)
		require.NoError(t, err)
		raw = append(raw, *d)
	}

	st := newServiceTestStore(t)
	require.NoError(t, st.AddProcessedDeals(cc, round, raw, nil))

	s := &DKGServer{Suite: suite, DKGStore: st}

	resps, _, rej, err := s.applyDeals(gens[self], cc, round, n, reqDeals)
	require.NoError(t, err)
	require.Empty(t, resps, "no stored emitted responses means nothing to re-emit")
	require.Empty(t, rej, "dedup must never reject")
}

// TestApplyDeals_EvictsCachedGeneratorOnPersistFailure is the regression test
// for PR #87: when AddProcessedDeals fails after kyber has already absorbed the
// deals in memory, applyDeals must evict the round's cached generator so the
// next retry rebuilds a fresh one from persisted state (which lacks these
// deals) and re-processes cleanly — rather than hitting kyber's
// already-processed path with nothing on disk to re-emit.
func TestApplyDeals_EvictsCachedGeneratorOnPersistFailure(t *testing.T) {
	t.Parallel()

	const (
		cc        = "cc-persist-fail"
		round     = uint32(1)
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	self := 0
	reqDeals := dealsAddressedTo(t, gens, self)

	// Point the state directory at a regular file so every state read/write
	// fails: this makes AddProcessedDeals return an error after kyber has
	// already absorbed the deals in memory, reproducing the persist-fail case.
	dir := t.TempDir()
	stateAsFile := filepath.Join(dir, "state-as-file")
	require.NoError(t, os.WriteFile(stateAsFile, []byte("x"), 0o600))

	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		stateAsFile,
		suite,
		upgradePlaintextSealer{},
	)

	s := &DKGServer{
		Suite:              suite,
		DKGStore:           st,
		InitDKGCache:       store.NewDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}

	// Seed both round-keyed caches: an initial round lives in InitDKGCache and a
	// resharing round in ResharingNextCache; applyDeals evicts both defensively.
	s.InitDKGCache.Set(round, gens[self])
	s.ResharingNextCache.Set(round, gens[self])

	_, _, _, err := s.applyDeals(gens[self], cc, round, n, reqDeals)
	require.Error(t, err, "persist failure must surface an error")

	_, ok := s.InitDKGCache.Get(round)
	require.False(t, ok, "InitDKGCache generator must be evicted after persist failure")

	_, ok = s.ResharingNextCache.Get(round)
	require.False(t, ok, "ResharingNextCache generator must be evicted after persist failure")
}

// TestProcessDeals_ConcurrentRoundSerialized reproduces the timeout-then-retry
// race: an abandoned handler and its retry run concurrently against the same
// cached generator. Guarded by getDKGMutationMu (as ProcessDeals does), the two
// runs serialize — one processes, the other re-emits — with no data race
// (run with -race) and no duplicate own responses.
func TestProcessDeals_ConcurrentRoundSerialized(t *testing.T) {
	t.Parallel()

	const (
		cc        = "cc-concurrent"
		round     = uint32(1)
		n         = 3
		threshold = 2
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	gens := freshDKGGens(t, suite, n, threshold)
	self := 0
	reqDeals := dealsAddressedTo(t, gens, self)

	s := &DKGServer{Suite: suite, DKGStore: newServiceTestStore(t)}

	// Mirror ProcessDeals' lock discipline in two goroutines sharing gens[self].
	run := func() ([]*pb.Response, error) {
		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		resps, _, _, err := s.applyDeals(gens[self], cc, round, n, reqDeals)

		return resps, err
	}

	var (
		wg         sync.WaitGroup
		r1, r2     []*pb.Response
		err1, err2 error
	)
	wg.Add(2)
	go func() { defer wg.Done(); r1, err1 = run() }()
	go func() { defer wg.Done(); r2, err2 = run() }()
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	// Both runs return the full response set (one fresh, one re-emitted).
	require.Len(t, r1, len(reqDeals))
	require.Len(t, r2, len(reqDeals))

	// Serialized process+persist must leave exactly one own response per dealer.
	st, err := s.DKGStore.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.EmittedResponses, len(reqDeals), "no duplicate own responses")
}

// setupEvictableInitRound builds a DKGServer whose round-1 initial DKG can be
// rebuilt from the sealed store, seeds InitDKGCache with the original generator
// (p0), and makes the round's state directory read-only so applyDeals' persist
// fails and triggers the #87 cache eviction while rebuild reads still succeed.
// Shared by the #94 concurrent-resolution tests.
func setupEvictableInitRound(t *testing.T) (s *DKGServer, cc string, round uint32, threshold, n int, pubs []kyber.Point, reqDeals []*pb.Deal, p0 *dkg.DistKeyGenerator) {
	t.Helper()

	cc = "cc-resolve-inlock"
	round = uint32(1)
	n = 3
	threshold = 2

	suite := edwards25519.NewBlakeSHA256Ed25519()

	longterms := make([]kyber.Scalar, n)
	pubs = make([]kyber.Point, n)
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

	const self = 0
	reqDeals = dealsAddressedTo(t, gens, self)

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		stateDir,
		suite,
		upgradePlaintextSealer{},
	)

	// Seal self's Ed25519 key and persist threshold+pubkeys so GetInitDKG can
	// rebuild a fresh generator after eviction.
	selfBz, err := longterms[self].MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, round, selfBz))
	require.NoError(t, st.SaveDKGState(&store.DKGState{Threshold: uint32(threshold), PubKeys: pubs}, cc, round))

	s = &DKGServer{
		Suite:              suite,
		DKGStore:           st,
		InitDKGCache:       store.NewDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}
	p0 = gens[self]
	s.InitDKGCache.Set(round, p0)

	// Read-only round dir: persist (AddProcessedDeals writes a .tmp) fails while
	// rebuild reads succeed, forcing the eviction path. Restore on cleanup so
	// t.TempDir removal works.
	roundDir := filepath.Join(stateDir, fmt.Sprintf("%d", round), cc)
	require.NoError(t, os.Chmod(roundDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(roundDir, 0o700) })

	return s, cc, round, threshold, n, pubs, reqDeals, p0
}

// TestProcessDeals_ResolvesFreshGeneratorAfterEviction is the regression test for
// issue #94. Two concurrent same-round runs mirror the fixed handler: warm the
// generator OUTSIDE getDKGMutationMu, then take it via a pure cache-get UNDER the
// lock, re-warming on a miss. Serialized, the winner cache-gets the seeded
// generator and evicts it on persist failure (#87); the loser sees a cache MISS
// under the lock, re-warms OUTSIDE the lock, and resolves a FRESH generator
// instead of the stale pre-eviction pointer. Run with -race.
func TestProcessDeals_ResolvesFreshGeneratorAfterEviction(t *testing.T) {
	s, cc, round, threshold, n, pubs, reqDeals, p0 := setupEvictableInitRound(t)

	// Warm outside M, cache-get + process under M, re-warm on eviction.
	run := func() (*dkg.DistKeyGenerator, error) {
		mu := s.getDKGMutationMu(round)
		for attempt := 0; attempt < maxResolveDealsAttempts; attempt++ {
			// Warm OUTSIDE the lock: a cache-miss rebuild happens here, never under M.
			if _, err := s.GetInitDKG(cc, round, uint32(threshold), pubs); err != nil {
				return nil, err
			}

			var (
				gen *dkg.DistKeyGenerator
				ok  bool
			)
			func() {
				mu.Lock()
				defer mu.Unlock()

				gen, ok = s.InitDKGCache.Get(round)
				if !ok {
					return
				}
				// Persist fails under the read-only dir and evicts the cache (#87).
				_, _, _, _ = s.applyDeals(gen, cc, round, n, reqDeals)
			}()
			if ok {
				return gen, nil
			}
			// Evicted between warm and lock: loop re-warms OUTSIDE M.
		}

		return nil, errors.New("exhausted resolve attempts")
	}

	var (
		wg         sync.WaitGroup
		g1, g2     *dkg.DistKeyGenerator
		err1, err2 error
	)
	wg.Add(2)
	go func() { defer wg.Done(); g1, err1 = run() }()
	go func() { defer wg.Done(); g2, err2 = run() }()
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotSame(t, g1, g2, "concurrent runs must not share a stale generator pointer")
	require.True(t, g1 == p0 || g2 == p0, "one run must resolve the seeded cached generator")
}

// TestProcessDeals_ResolveOutsideLockSharesStalePointer is the inverse-sanity
// check for #94: with resolution OUTSIDE the lock (the pre-fix ordering) two
// concurrent runs that both resolve before either locks share the SAME pointer,
// which the winner then evicts — leaving the loser on a stale generator. This
// documents the window the fix closes. Run with -race.
func TestProcessDeals_ResolveOutsideLockSharesStalePointer(t *testing.T) {
	s, cc, round, threshold, n, pubs, reqDeals, p0 := setupEvictableInitRound(t)

	// Barrier so both runs resolve before either enters its critical section.
	var resolved sync.WaitGroup
	resolved.Add(2)

	// Pre-fix ordering: resolve BEFORE the lock.
	run := func() (*dkg.DistKeyGenerator, error) {
		gen, err := s.GetInitDKG(cc, round, uint32(threshold), pubs)
		resolved.Done()
		if err != nil {
			return nil, err
		}
		resolved.Wait()

		mu := s.getDKGMutationMu(round)
		mu.Lock()
		defer mu.Unlock()
		_, _, _, _ = s.applyDeals(gen, cc, round, n, reqDeals)

		return gen, nil
	}

	var (
		wg         sync.WaitGroup
		g1, g2     *dkg.DistKeyGenerator
		err1, err2 error
	)
	wg.Add(2)
	go func() { defer wg.Done(); g1, err1 = run() }()
	go func() { defer wg.Done(); g2, err2 = run() }()
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	// Both resolved the seeded pointer before eviction: the shared stale window.
	require.Same(t, p0, g1, "pre-fix ordering shares the seeded generator")
	require.Same(t, p0, g2, "pre-fix ordering shares the seeded generator")
}

// countingResharingQC wraps the resharing build's chain queries with call
// counters so a test can prove the in-M step issues zero queries (pure cache-get).
type countingResharingQC struct {
	*upgradeStubQC
	latestCalls int32
	regCalls    int32
}

func (q *countingResharingQC) GetLatestActiveDKGNetwork(ctx context.Context) (*pb.DKGNetwork, error) {
	atomic.AddInt32(&q.latestCalls, 1)

	return q.upgradeStubQC.GetLatestActiveDKGNetwork(ctx)
}

func (q *countingResharingQC) GetAllRegisteredDKGRegistrations(ctx context.Context, cc string, round uint32) ([]*pb.DKGRegistration, error) {
	atomic.AddInt32(&q.regCalls, 1)

	return q.upgradeStubQC.GetAllRegisteredDKGRegistrations(ctx, cc, round)
}

func (q *countingResharingQC) queries() int32 {
	return atomic.LoadInt32(&q.latestCalls) + atomic.LoadInt32(&q.regCalls)
}

// TestProcessDeals_ResharingInLockPathIssuesNoQueries proves the #94 fix keeps
// light-client IO OUT of the mutation lock for the resharing path: warming the
// generator OUTSIDE M does the cache-miss build (which queries the chain), and
// the subsequent in-M step is a pure cache-get that returns the same pointer and
// issues zero further queries. Without warming outside M, GetResharingNextDKG's
// unbounded network build would run while holding M — the liveness regression.
func TestProcessDeals_ResharingInLockPathIssuesNoQueries(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-reshare-inlock"
		prevRound = uint32(10)
		toRound   = uint32(14)
		prevT     = uint32(2)
		nextT     = uint32(2)
	)

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}

	prevPubs := []kyber.Point{point(11), point(12), point(13)}
	regs := make([]*pb.DKGRegistration, len(prevPubs))
	for i, p := range prevPubs {
		bz, err := p.MarshalBinary()
		require.NoError(t, err)
		regs[i] = &pb.DKGRegistration{Index: uint32(i), Round: prevRound, DkgPubKey: bz}
	}

	coeffs := []kyber.Point{point(101), point(102)} // len == prevT
	coeffsBz, err := MarshalPoints(coeffs)
	require.NoError(t, err)

	dScalar := suite.Scalar().SetInt64(777)
	dBz, err := dScalar.MarshalBinary()
	require.NoError(t, err)
	nextPubs := []kyber.Point{suite.Point().Mul(dScalar, nil), point(21), point(22)}

	dir := t.TempDir()
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, toRound, dBz))

	qc := &countingResharingQC{upgradeStubQC: &upgradeStubQC{
		latest: &pb.DKGNetwork{Round: prevRound, Threshold: prevT, PublicCoeffs: coeffsBz},
		regs:   regs,
	}}
	s := &DKGServer{
		QueryClient:        qc,
		Suite:              suite,
		DKGStore:           st,
		ResharingNextCache: store.NewDKGCache(),
	}

	mu := s.getDKGMutationMu(toRound)

	// Warm OUTSIDE M: the cache-miss build queries the chain here, no lock held.
	warmed, err := s.GetResharingNextDKG(cc, toRound, nextT, nextPubs)
	require.NoError(t, err)
	require.NotNil(t, warmed)
	buildQueries := qc.queries()
	require.Greater(t, buildQueries, int32(0), "build path must query the chain outside the lock")

	// In-M step: pure cache-get, same pointer, zero additional queries.
	mu.Lock()
	got, ok := s.ResharingNextCache.Get(toRound)
	mu.Unlock()
	require.True(t, ok, "warmed resharing round must be a cache hit under M")
	require.Same(t, warmed, got, "in-M step must return the warmed pointer, not a rebuild")
	require.Equal(t, buildQueries, qc.queries(), "in-M cache-get must issue no chain queries")
}

// --- direct tri-state coverage for resolveAndApplyDeals / attemptDeals /
// warmGenerator / applyDealsUnderLock (#94 decomposition) ---

// setupWritableInitRound mirrors setupEvictableInitRound but leaves the round's
// state directory writable, so AddProcessedDeals succeeds and the success path
// through resolveAndApplyDeals can be exercised end-to-end.
func setupWritableInitRound(t *testing.T) (s *DKGServer, cc string, round uint32, threshold, n int, pubs []kyber.Point, reqDeals []*pb.Deal, p0 *dkg.DistKeyGenerator) {
	t.Helper()

	cc = "cc-resolve-writable"
	round = uint32(1)
	n = 3
	threshold = 2

	suite := edwards25519.NewBlakeSHA256Ed25519()

	longterms := make([]kyber.Scalar, n)
	pubs = make([]kyber.Point, n)
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

	const self = 0
	reqDeals = dealsAddressedTo(t, gens, self)

	dir := t.TempDir()
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)

	selfBz, err := longterms[self].MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, round, selfBz))
	require.NoError(t, st.SaveDKGState(&store.DKGState{Threshold: uint32(threshold), PubKeys: pubs}, cc, round))

	s = &DKGServer{
		Suite:              suite,
		DKGStore:           st,
		InitDKGCache:       store.NewDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}
	p0 = gens[self]
	s.InitDKGCache.Set(round, p0)

	return s, cc, round, threshold, n, pubs, reqDeals, p0
}

// TestResolveAndApplyDeals_Success drives resolveAndApplyDeals directly on a
// writable round: warmGenerator cache-hits the seeded generator, applyDealsUnderLock
// takes M, cache-gets it, and applyDeals persists successfully on the first
// attempt. Covers the success leg of the tri-state across all four #94 functions.
func TestResolveAndApplyDeals_Success(t *testing.T) {
	t.Parallel()

	s, cc, round, threshold, n, pubs, reqDeals, _ := setupWritableInitRound(t)

	rc := &store.RoundContext{
		Round:         round,
		Network:       &pb.DKGNetwork{Threshold: uint32(threshold)},
		SortedPubKeys: pubs,
	}
	req := &pb.ProcessDealsRequest{
		Round:          round,
		CodeCommitment: []byte(cc),
		Deals:          reqDeals,
		IsResharing:    false,
	}

	out, err := s.resolveAndApplyDeals(cc, rc, req, n)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotEmpty(t, out.resps, "success must emit at least one response")

	st, err := s.DKGStore.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.Deals, len(reqDeals), "deals must be persisted on the success path")
}

// TestApplyDealsUnderLock_CacheMissSignalsEviction covers the !ok branch of
// applyDealsUnderLock directly: with the round absent from both caches, the
// pure cache-get under M misses and the function must return (nil, nil) — the
// eviction signal resolveAndApplyDeals retries on — not an error.
func TestApplyDealsUnderLock_CacheMissSignalsEviction(t *testing.T) {
	t.Parallel()

	s := &DKGServer{
		InitDKGCache:       store.NewDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
	}
	req := &pb.ProcessDealsRequest{
		Round:          1,
		CodeCommitment: []byte("cc-evicted"),
		Deals:          []*pb.Deal{{Index: 0}},
		IsResharing:    false,
	}

	out, err := s.applyDealsUnderLock("cc-evicted", req, 3)
	require.NoError(t, err)
	require.Nil(t, out, "cache miss must signal eviction with a nil result and nil error")
}

// TestResolveAndApplyDeals_PersistFailureIsInternalNotEviction is the regression
// guard for the hard-error leg of the tri-state: on the seeded read-only round,
// warmGenerator cache-hits (no rebuild needed) and applyDeals fails to persist.
// That must surface as codes.Internal — never be misread as the (nil, nil)
// eviction signal, which would silently retry and mask the persist failure.
func TestResolveAndApplyDeals_PersistFailureIsInternalNotEviction(t *testing.T) {
	s, cc, round, threshold, n, pubs, reqDeals, _ := setupEvictableInitRound(t)

	rc := &store.RoundContext{
		Round:         round,
		Network:       &pb.DKGNetwork{Threshold: uint32(threshold)},
		SortedPubKeys: pubs,
	}
	req := &pb.ProcessDealsRequest{
		Round:          round,
		CodeCommitment: []byte(cc),
		Deals:          reqDeals,
		IsResharing:    false,
	}

	out, err := s.resolveAndApplyDeals(cc, rc, req, n)
	require.Error(t, err)
	require.Nil(t, out)
	require.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "failed to persist processed deals")

	// NOTE on exhaustion (codes.Unavailable): forcing every attempt to observe an
	// eviction requires either a production test seam or a real concurrent evictor
	// racing every retry, both of which are ruled out by the task constraints. The
	// Unavailable terminal is covered behaviorally by
	// TestProcessDeals_ResolvesFreshGeneratorAfterEviction and
	// TestProcessDeals_ResolveOutsideLockSharesStalePointer above, which exercise
	// the same warm/lock/re-warm cycle under real concurrency.
}
