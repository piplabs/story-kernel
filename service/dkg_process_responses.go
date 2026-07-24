package service

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *DKGServer) ProcessResponses(_ context.Context, req *pb.ProcessResponsesRequest) (*pb.ProcessResponsesResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessResponsesRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"num_responses":   len(req.GetResponses()),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request")
	}

	// Validate code commitment
	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("failed to validate code commitment: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "failed to validate code commitment")
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	// Bounds-check references for the per-item loop:
	//   dealerCount     — upper bound for outer Response.Index (the dealer).
	//   complainerCount — upper bound for inner VssResponse.Index (the
	//                     responder/complainer).
	// Non-resharing rounds have a single committee acting as both. In
	// resharing, dealers live in the OLD committee and complainers live
	// in the NEW committee, so the bounds diverge.
	var dealerCount, complainerCount int

	// latestActiveRound is the prev (dealer) committee round whose sealed key signs
	// resharing justifications. Only set for resharing.
	var latestActiveRound uint32

	var distKeyGens []*dkg.DistKeyGenerator
	if !req.GetIsResharing() {
		dealerCount = len(rc.SortedPubKeys)
		complainerCount = len(rc.SortedPubKeys)

		distKeyGen, err := s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild initial distributed key generator: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial distributed key generator")
		}
		distKeyGens = append(distKeyGens, distKeyGen)
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			log.Errorf("failed to get the latest active round of DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to get the latest active round of DKG")
		}
		// Defence in depth against a future regression in
		// GetLatestActiveDKGNetwork that returns (nil, nil) on an
		// uninitialised state.
		if latest == nil || latest.GetTotal() == 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"resharing requires an active prior DKG network")
		}

		dealerCount = int(latest.GetTotal())    // OLD committee
		complainerCount = len(rc.SortedPubKeys) // NEW committee
		latestActiveRound = latest.GetRound()   // signs resharing justifications

		prevDistKeyGen, err := s.GetResharingPrevDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys, latest)
		if err != nil {
			log.Infof("failed to load or rebuild the previous distributed key generator for resharing, skip processing responses for the previous distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, prevDistKeyGen)
		}

		nextDistKeyGen, err := s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the next distributed key generator for resharing, skip processing responses for the next distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, nextDistKeyGen)
		}
	}

	// Fail loudly if no DistKeyGenerator is available — without this guard
	// the per-item loop would silently treat every input as processed
	// (the empty for-range exits without setting any flags).
	if len(distKeyGens) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no DistKeyGenerator available for this round (node not a member of the required committee(s))")
	}

	// Process the responses. A response is considered rejected iff it fails
	// against EVERY configured DistKeyGenerator with a non-idempotent error.
	// For resharing (prev+next), accepted-by-any wins. If every generator
	// returns an idempotent "already existing" error the response is silently
	// skipped (NOT added to rejected_responses) so the client doesn't retry
	// something kyber has already absorbed.
	//
	// rejected may contain duplicates of the same response when both a
	// proto-conversion failure AND a generator failure happen on the same
	// item; the CL deduplicates via a per-batch map keyed by (Index, inner
	// Index) so we don't bother deduping here.
	// Serialize the shared DistKeyGenerator mutation with the other DKG-mutating
	// RPCs for this round (see dkgMutationMu). Held across process+persist so a
	// retry sees a fully persisted state and re-emits its emitted justifications
	// deterministically. Lock order dkgMutationMu -> stateMu stays one-directional.
	var (
		justifications []*pb.Justification
		processed      int
		rejected       []*pb.Response
	)
	if err := s.withRoundMutation(req.GetRound(), func() error {
		var err error
		justifications, processed, rejected, err = s.applyResponses(
			distKeyGens, req.GetIsResharing(), codeCommitmentHex, req.GetRound(),
			latestActiveRound, dealerCount, complainerCount, req.GetResponses(),
		)

		return err
	}); err != nil {
		log.Errorf("failed to add processed responses to the DKG state: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to add processed responses to the DKG state")
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"processed":       processed,
		"rejected":        len(rejected),
	}).Info("Processed responses")

	return &pb.ProcessResponsesResponse{
		Justifications:    justifications,
		RejectedResponses: rejected,
	}, nil
}

// applyResponses runs each response through the configured generators, signs any
// resharing justification kyber left unsigned, persists the processed responses
// with the justifications this node generated (atomically), and returns the
// justifications to forward, the count of responses persisted, and the rejected
// ones. Mirrors applyDeals (process+persist in one call) so ProcessResponses can
// hold the mutex across both with a single Lock/Unlock. Extracted so the signing
// wiring is testable without the enclave-gated RPC entry point.
func (s *DKGServer) applyResponses(
	distKeyGens []*dkg.DistKeyGenerator,
	isResharing bool,
	codeCommitmentHex string,
	round uint32,
	latestActiveRound uint32,
	dealerCount, complainerCount int,
	reqResponses []*pb.Response,
) ([]*pb.Justification, int, []*pb.Response, error) {
	var (
		justifications []*pb.Justification
		resps          []dkg.Response
		emittedJusts   []dkg.Justification
		rejected       []*pb.Response
	)

	// Dealer key that signs resharing justifications, loaded at most once and
	// only when a justification actually needs it (only a prev-committee dealer
	// holds it).
	dealerKey := &lazy[kyber.Scalar]{load: func() (kyber.Scalar, error) {
		return s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, latestActiveRound)
	}}

	// EmittedJustifications, loaded at most once and only for a retried complaint.
	storedJusts := &lazy[[]dkg.Justification]{load: func() ([]dkg.Justification, error) {
		st, err := s.DKGStore.LoadDKGState(codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}

		return st.EmittedJustifications, nil
	}}

	for _, response := range reqResponses {
		resp := types.ConvertToVSSResp(response)

		// Defence in depth: bounds-check the dealer AND complainer indices
		// before kyber. processResharingResponse lazily inserts aggregators
		// keyed by resp.Index without validation, so an out-of-range index
		// could grow the aggregators map inside the enclave. In resharing,
		// dealers are old-committee members and complainers are new-committee
		// members.
		if int(resp.Index) >= dealerCount {
			rejected = append(rejected, response)

			continue
		}
		if resp.Response != nil && int(resp.Response.Index) >= complainerCount {
			rejected = append(rejected, response)

			continue
		}

		res, err := s.processResponse(distKeyGens, resp, isResharing, dealerKey, round, codeCommitmentHex)
		if err != nil {
			// Transient dealer-key-load failure. Return before AddProcessedResponses
			// so nothing is persisted for this batch; the CL retries the whole call
			// and the justification is re-generated and signed once the key is
			// available (kyber's resharing-own-deal path re-emits on every call, so
			// the in-memory generator mutation from this call is not lost on retry).
			return nil, 0, nil, err
		}
		justifications = append(justifications, res.pbJusts...)
		emittedJusts = append(emittedJusts, res.emitted...)

		if shouldReEmitJustification(res, resp) {
			pbJust, rerr := reEmitJustification(storedJusts, resp)
			switch {
			case rerr != nil:
				// Cannot fail the RPC (justifications already converted); treat as none-stored.
				log.WithFields(log.Fields{
					"round":           round,
					"code_commitment": codeCommitmentHex,
				}).Errorf("failed to re-emit stored justification: %v", rerr)
			case pbJust != nil:
				justifications = append(justifications, pbJust)
			default:
				// Normal on any node that is not the complained-of dealer: a
				// complaint is broadcast to everyone but only the dealer stores a
				// justification for it, so most nodes have nothing to re-emit. The
				// one problematic case (the dealer's persist failed) is already
				// logged at Error where AddProcessedResponses fails, so this is Debug.
				log.WithFields(log.Fields{
					"round":            round,
					"code_commitment":  codeCommitmentHex,
					"dealer_index":     resp.Index,
					"complainer_index": resp.Response.Index,
				}).Debug("response already processed with no stored justification to re-emit; skipping")
			}
		}

		if !res.processed {
			rejected = append(rejected, response)

			continue
		}

		resps = append(resps, *resp)
	}

	if len(resps) > 0 {
		if err := s.DKGStore.AddProcessedResponses(codeCommitmentHex, round, resps, emittedJusts); err != nil {
			return nil, 0, nil, err
		}
	}

	return justifications, len(resps), rejected, nil
}

// responseResult summarizes processing one response against every generator.
type responseResult struct {
	processed  bool // at least one generator accepted it (real success or idempotent)
	idempotent bool // at least one generator reported it already absorbed (a retry)
	freshJust  bool // kyber (re-)generated a justification this call
	pbJusts    []*pb.Justification
	emitted    []dkg.Justification // signed justifications to persist
}

// processResponse runs resp through every generator, signs any fresh resharing
// justification, and reports the outcome. Reject only when EVERY generator
// returns a real (non-idempotent) error; in resharing (prev+next) only one
// generator typically owns a given response. Returns a non-nil error only for a
// transient dealer-key-load failure, which must abort the batch so the CL retries
// (see signJustificationIfNeeded); all other drops are folded into the result.
func (s *DKGServer) processResponse(
	distKeyGens []*dkg.DistKeyGenerator,
	resp *dkg.Response,
	isResharing bool,
	dealerKey *lazy[kyber.Scalar],
	round uint32,
	codeCommitmentHex string,
) (responseResult, error) {
	var complainerIdx uint32
	if resp.Response != nil {
		complainerIdx = resp.Response.Index
	}

	var res responseResult
	for _, distKeyGen := range distKeyGens {
		j, err := distKeyGen.ProcessResponse(resp)
		if err != nil {
			// Log only indices, never the full VSSResponse struct.
			log.WithFields(log.Fields{
				"round":            round,
				"code_commitment":  codeCommitmentHex,
				"dealer_index":     resp.Index,
				"complainer_index": complainerIdx,
			}).Errorf("failed to process the response: %v", err)

			if isAlreadyProcessedErr(err) {
				res.processed = true
				res.idempotent = true
			}

			continue
		}

		res.processed = true
		if j == nil {
			continue
		}

		signed, err := s.signJustificationIfNeeded(isResharing, dealerKey, j, round, codeCommitmentHex)
		if err != nil {
			// Transient key-load failure: abort so the caller returns an error and
			// the CL retries. Nothing persisted yet, so the retry re-generates this.
			return res, err
		}
		if !signed {
			continue
		}

		pbJust, convErr := types.ConvertToJustificationProto(j)
		if convErr != nil {
			// Drop only this justification (unreachable on Ed25519); the response
			// still flows to resps so kyber and the store stay consistent. Log
			// only the index to avoid leaking SecShare.
			log.WithFields(log.Fields{
				"round":               round,
				"code_commitment":     codeCommitmentHex,
				"justification_index": j.Index,
			}).Errorf("failed to convert generated justification to proto; justification dropped: %v", convErr)

			continue
		}

		res.pbJusts = append(res.pbJusts, pbJust)
		// Keep the kyber form so ProcessResponses persists it with the response.
		res.emitted = append(res.emitted, *j)
		res.freshJust = true
	}

	return res, nil
}

// signJustificationIfNeeded signs an unsigned resharing justification with the
// lazily-loaded dealer key and reports whether it was signed. A key-LOAD failure is
// transient (sealer/TEE momentarily unavailable): it returns an error so the CL retries
// and re-signs once the key loads. A signing failure on a loaded key is deterministic,
// so it drops the justification (false, nil) instead of forwarding it unsigned.
// Initial-DKG justifications arrive kyber-signed and are left untouched.
func (s *DKGServer) signJustificationIfNeeded(
	isResharing bool,
	dealerKey *lazy[kyber.Scalar],
	j *dkg.Justification,
	round uint32,
	codeCommitmentHex string,
) (bool, error) {
	if !isResharing || len(j.Justification.Signature) != 0 {
		return true, nil
	}

	key, err := dealerKey.Get()
	if err != nil {
		// Transient: surface so the CL retries instead of dropping the justification.
		log.WithFields(log.Fields{
			"round":           round,
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to load dealer key to sign resharing justification; retrying: %v", err)

		return false, errors.Wrap(err, "load dealer key to sign resharing justification")
	}

	if err := signResharingJustification(s.Suite, key, j); err != nil {
		// Deterministic: retrying will not help, so drop this justification.
		log.WithFields(log.Fields{
			"round":               round,
			"code_commitment":     codeCommitmentHex,
			"justification_index": j.Index,
		}).Errorf("failed to sign resharing justification; dropping: %v", err)

		return false, nil
	}

	// Confirm this node signed a resharing justification with its prev-committee key.
	log.WithFields(log.Fields{
		"round":               round,
		"code_commitment":     codeCommitmentHex,
		"justification_index": j.Index,
	}).Info("signed resharing justification")

	return true, nil
}

// shouldReEmitJustification reports whether a retried response needs its
// justification recovered from storage. Unlike deals — where a response is either
// freshly generated or re-emitted — a response runs through prev+next generators,
// so it can be idempotent on one and produce a fresh justification on another;
// re-emit only when it was idempotent AND no fresh justification was produced. And
// only complaints ever produce justifications, so approvals are skipped (which also
// keeps the not-found warning meaningful).
func shouldReEmitJustification(res responseResult, resp *dkg.Response) bool {
	return res.idempotent && !res.freshJust &&
		resp.Response != nil && resp.Response.Status == vss.StatusComplaint
}

// reEmitJustification returns the signed justification this node persisted for
// the complaint in resp so a retried response recovers it, or nil if none was
// stored (keyed by dealer + complainer index, at most one per pair).
func reEmitJustification(stored *lazy[[]dkg.Justification], resp *dkg.Response) (*pb.Justification, error) {
	emitted, err := stored.Get()
	if err != nil {
		return nil, err
	}

	for i := range emitted {
		ej := &emitted[i]
		if ej.Index == resp.Index && ej.Justification.Index == resp.Response.Index {
			return types.ConvertToJustificationProto(ej)
		}
	}

	return nil, nil
}

func validateProcessResponsesRequest(req *pb.ProcessResponsesRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	if len(req.GetResponses()) == 0 {
		return errors.New("empty responses to process")
	}

	return nil
}

// signResharingJustification Schnorr-signs the inner vss.Justification with the
// dealer's longterm key when kyber left it unsigned. It signs the exact bytes the
// CL verifies (j.Justification.Hash(suite)) and no-ops when a signature is already
// present, so the initial-DKG path (kyber-signed) is never overwritten.
//
// Why this is done manually: on the resharing path kyber's processResharingResponse
// (go.dedis.ch/kyber/v4@v4.0.0-pre2, share/dkg/pedersen/dkg.go) builds the
// justification WITHOUT a Signature — unlike the initial-DKG path, where
// vss.Dealer.ProcessResponse signs it internally via schnorr.Sign. This mirrors
// that signed path exactly (same key, same j.Hash). Kyber fixed this in v4.0.2 by
// rewriting justifications to a uniformly-signed JustificationBundle (d.sign), so
// once the kernel upgrades kyber past pre2 this manual signing can be removed.
func signResharingJustification(suite *edwards25519.SuiteEd25519, longterm kyber.Scalar, j *dkg.Justification) error {
	if j == nil || j.Justification == nil || len(j.Justification.Signature) != 0 {
		return nil
	}

	sig, err := schnorr.Sign(suite, longterm, j.Justification.Hash(suite))
	if err != nil {
		return err
	}

	j.Justification.Signature = sig

	return nil
}
