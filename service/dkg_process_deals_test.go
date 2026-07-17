package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
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
