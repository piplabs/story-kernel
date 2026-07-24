package service

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errKyberDealAlreadyProcessed, errKyberResponseAlreadyExists and
// errKyberJustificationOnApproval mirror the idempotent-error strings kyber
// returns when the cached DistKeyGenerator has already absorbed an artifact
// on a prior call. They are kept as locally-defined sentinels purely to
// centralise the strings and document the source — see the NOTE on
// isAlreadyProcessedErr for why we still match by substring rather than
// errors.Is.
//
// Source: go.dedis.ch/kyber/v4@v4.0.0-pre2/share/vss/pedersen/vss.go
//   - line 552: var errDealAlreadyProcessed (package-private)
//   - line 639: errors.New("vss: justification received for an approval")
//   - line 656: errors.New("vss: already existing response from same origin")
var (
	errKyberDealAlreadyProcessed    = errors.New("vss: verifier already received a deal")
	errKyberResponseAlreadyExists   = errors.New("vss: already existing response from same origin")
	errKyberJustificationOnApproval = errors.New("vss: justification received for an approval")
)

// isAlreadyProcessedErr returns true when err indicates the cached
// DistKeyGenerator has already absorbed the artifact on a prior call. The
// kernel silently skips these so the CL doesn't retry forever.
//
// NOTE: kyber v4.0.0-pre2 does NOT expose these as exported sentinels —
// errDealAlreadyProcessed is package-private, and the other two are inline
// errors.New(...) created on every call. errors.Is therefore cannot match
// any of the three (no exported reference for the first; non-sentinel for
// the others) and kyber does not wrap with %w, so chain-unwrap also fails.
// String matching is the only option today. If a future kyber release starts
// exporting these as sentinels and wrapping them with %w, switch to
// errors.Is against the kyber-exported values and remove the local sentinels
// above.
func isAlreadyProcessedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, errKyberDealAlreadyProcessed.Error()) ||
		strings.Contains(msg, errKyberResponseAlreadyExists.Error()) ||
		strings.Contains(msg, errKyberJustificationOnApproval.Error())
}

// maxResolveDealsAttempts bounds the warm->lock->cache-get retry loop so a
// persistent evict/re-warm cycle returns Unavailable instead of spinning.
const maxResolveDealsAttempts = 3

// processedDeals carries applyDeals' output out of the locked closure. A nil
// result with a nil error signals an eviction, so the caller re-warms.
type processedDeals struct {
	resps     []*pb.Response
	persisted int
	rejected  []*pb.Deal
}

// ProcessDeals process the deals. It is assumed that the deal has been correctly delivered to the corresponding recipient index.
func (s *DKGServer) ProcessDeals(_ context.Context, req *pb.ProcessDealsRequest) (*pb.ProcessDealsResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	if err := validateProcessDealsInput(req, codeCommitmentHex); err != nil {
		return nil, err
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	dealerCount, err := s.resolveDealerCount(rc, req)
	if err != nil {
		return nil, err
	}

	out, err := s.resolveAndApplyDeals(codeCommitmentHex, rc, req, dealerCount)
	if err != nil {
		return nil, err
	}

	// responses = total emitted this call (incl. re-emitted on retry);
	// persisted_deals = deals newly stored this call (0 on a pure retry).
	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"responses":       len(out.resps),
		"persisted_deals": out.persisted,
		"rejected":        len(out.rejected),
	}).Info("Processed deals")

	return &pb.ProcessDealsResponse{
		CodeCommitment: req.GetCodeCommitment(),
		Round:          req.GetRound(),
		Responses:      out.resps,
		RejectedDeals:  out.rejected,
	}, nil
}

// validateProcessDealsInput runs the request and code-commitment checks,
// returning a ready-to-return status error on failure.
func validateProcessDealsInput(req *pb.ProcessDealsRequest, codeCommitmentHex string) error {
	if err := validateProcessDealsRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"num_deals":       len(req.GetDeals()),
		}).Errorf("invalid request: %v", err)

		return status.Errorf(codes.InvalidArgument, "invalid request")
	}

	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("failed to validate code commitment: %v", err)

		return status.Errorf(codes.InvalidArgument, "failed to validate code commitment")
	}

	return nil
}

// resolveDealerCount upper-bounds Deal.Index. Non-resharing has a single
// committee acting as dealers; resharing dealers are members of the PRIOR
// active committee (kyber's c.OldNodes inside the next-DKG).
func (s *DKGServer) resolveDealerCount(rc *store.RoundContext, req *pb.ProcessDealsRequest) (int, error) {
	if !req.GetIsResharing() {
		return len(rc.SortedPubKeys), nil
	}

	latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
	if err != nil {
		log.Errorf("failed to get the latest active round of DKG: %v", err)

		return 0, status.Errorf(codes.Internal, "failed to get the latest active round of DKG")
	}
	if latest == nil || latest.GetTotal() == 0 {
		return 0, status.Errorf(codes.FailedPrecondition,
			"resharing requires an active prior DKG network")
	}

	return int(latest.GetTotal()), nil
}

// resolveAndApplyDeals retries a warm+apply attempt until it yields deals or is
// exhausted, re-warming on each eviction (the #94 warm-vs-lock race). Exhaustion
// returns Unavailable.
func (s *DKGServer) resolveAndApplyDeals(
	codeCommitmentHex string,
	rc *store.RoundContext,
	req *pb.ProcessDealsRequest,
	dealerCount int,
) (*processedDeals, error) {
	for attempt := 0; attempt < maxResolveDealsAttempts; attempt++ {
		out, err := s.attemptDeals(codeCommitmentHex, rc, req, dealerCount)
		if err != nil {
			return nil, err
		}
		if out != nil {
			return out, nil
		}
		// Evicted between warm and lock: re-warm outside M and retry.
	}

	log.Errorf("failed to resolve a live generator for round %d after %d attempts", req.GetRound(), maxResolveDealsAttempts)

	return nil, status.Errorf(codes.Unavailable, "failed to resolve a live generator")
}

// attemptDeals runs one pass: warm the generator outside M, then apply the deals under M.
// A nil result with a nil error means the round was evicted between the warm and the lock,
// signalling the caller to retry.
func (s *DKGServer) attemptDeals(
	codeCommitmentHex string,
	rc *store.RoundContext,
	req *pb.ProcessDealsRequest,
	dealerCount int,
) (*processedDeals, error) {
	if err := s.warmGenerator(codeCommitmentHex, rc, req); err != nil {
		log.Errorf("failed to load or rebuild distributed key generator: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load or rebuild distributed key generator")
	}

	out, err := s.applyDealsUnderLock(codeCommitmentHex, req, dealerCount)
	if err != nil {
		log.Errorf("failed to persist processed deals: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to persist processed deals")
	}

	return out, nil
}

// warmGenerator get-or-builds the round's generator OUTSIDE M (a cache-miss build does
// light-client IO for resharing). The pointer is discarded so callers re-fetch it under
// M via a pure cache-get, seeing an eviction instead of reusing a stale pointer.
func (s *DKGServer) warmGenerator(codeCommitmentHex string, rc *store.RoundContext, req *pb.ProcessDealsRequest) error {
	if !req.GetIsResharing() {
		_, err := s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		return err
	}

	_, err := s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)

	return err
}

// applyDealsUnderLock takes M(round), cache-gets the generator, and runs applyDeals.
// A nil result with a nil error means the round was evicted between warm and lock, so
// the caller re-warms. M stays a leaf: only a cache-get and applyDeals run under it.
func (s *DKGServer) applyDealsUnderLock(codeCommitmentHex string, req *pb.ProcessDealsRequest, dealerCount int) (*processedDeals, error) {
	var out *processedDeals
	err := s.withRoundMutation(req.GetRound(), func() error {
		// Pure cache-get under M (no build, no IO): a miss means the round was evicted.
		var (
			distKeyGen *dkg.DistKeyGenerator
			ok         bool
		)
		if !req.GetIsResharing() {
			distKeyGen, ok = s.InitDKGCache.Get(req.GetRound())
		} else {
			distKeyGen, ok = s.ResharingNextCache.Get(req.GetRound())
		}
		if !ok {
			return nil // evicted; out stays nil so the caller re-warms
		}

		resps, persisted, rejected, err := s.applyDeals(distKeyGen, codeCommitmentHex, req.GetRound(), dealerCount, req.GetDeals())
		if err != nil {
			return err
		}
		out = &processedDeals{resps: resps, persisted: persisted, rejected: rejected}

		return nil
	})

	return out, err
}

// applyDeals runs each incoming deal through the cached DistKeyGenerator,
// persisting each deal with the response it generated. On a retried deal that
// kyber already absorbed, it re-emits the stored response instead of losing the
// verifier's approval.
func (s *DKGServer) applyDeals(
	distKeyGen *dkg.DistKeyGenerator,
	codeCommitmentHex string,
	round uint32,
	dealerCount int,
	reqDeals []*pb.Deal,
) ([]*pb.Response, int, []*pb.Deal, error) {
	var (
		pbResps      []*pb.Response
		deals        []dkg.Deal
		emittedResps []dkg.Response
		rejected     []*pb.Deal
	)

	// EmittedResponses are loaded from disk at most once, and only if a retried
	// deal actually needs one — a normal call never reads state back.
	storedEmitted := &lazy[[]dkg.Response]{load: func() ([]dkg.Response, error) {
		st, err := s.DKGStore.LoadDKGState(codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}

		return st.EmittedResponses, nil
	}}

	for _, d := range reqDeals {
		deal := types.ConvertToDeal(d)

		// Defence in depth: bounds-check the dealer index before kyber.
		// kyber's ProcessDeal also rejects out-of-range indices, but a
		// pre-check keeps the error path symmetric with the other two
		// handlers and avoids exercising kyber's internal lookup tables
		// with attacker-chosen indices.
		if int(deal.Index) >= dealerCount {
			rejected = append(rejected, d)

			continue
		}

		resp, err := distKeyGen.ProcessDeal(deal)
		switch {
		case err == nil:
			pbResps = append(pbResps, types.ConvertToRespProto(resp))
			deals = append(deals, *deal)
			emittedResps = append(emittedResps, *resp)

		case isAlreadyProcessedErr(err):
			// Retried deal kyber already absorbed: re-emit the response stored
			// for it so the verifier's approval is not lost. Never rejected.
			pbResp, rerr := reEmitResponse(storedEmitted, deal.Index)
			if rerr != nil {
				return nil, 0, nil, rerr
			}
			if pbResp != nil {
				// Recovery path: confirm the stored response was recovered on retry.
				log.WithFields(log.Fields{
					"round":           round,
					"code_commitment": codeCommitmentHex,
					"sender_index":    deal.Index,
				}).Info("re-emitted stored response for retried deal")

				pbResps = append(pbResps, pbResp)
			} else {
				// No stored response (e.g. crash between processing and persist).
				log.WithFields(log.Fields{
					"round":           round,
					"code_commitment": codeCommitmentHex,
					"sender_index":    deal.Index,
				}).Warn("deal already processed but no stored response to re-emit; skipping")
			}

		default:
			log.WithFields(log.Fields{
				"round":           round,
				"code_commitment": codeCommitmentHex,
				"sender_index":    deal.Index,
			}).Errorf("failed to process the deal: %v", err)

			rejected = append(rejected, d)
		}
	}

	// Persist deals and their generated responses atomically so a retry after a
	// dropped connection can re-emit the responses instead of losing them.
	if len(deals) > 0 {
		if err := s.DKGStore.AddProcessedDeals(codeCommitmentHex, round, deals, emittedResps); err != nil {
			// Persist failed after kyber absorbed the deals in memory. Evict the
			// round's cached generator so the retry rebuilds from persisted state
			// (which lacks these deals) and re-processes cleanly. The generator is
			// in InitDKGCache or ResharingNextCache (both round-keyed; Delete is a
			// no-op when absent, so evicting both is safe).
			s.InitDKGCache.Delete(round)
			s.ResharingNextCache.Delete(round)

			return nil, 0, nil, err
		}
	}

	return pbResps, len(deals), rejected, nil
}

// reEmitResponse returns the response this node persisted for dealerIndex on a
// prior call so a retried deal recovers it, or nil if none was stored (keyed by
// dealer index, at most one per index).
func reEmitResponse(stored *lazy[[]dkg.Response], dealerIndex uint32) (*pb.Response, error) {
	emitted, err := stored.Get()
	if err != nil {
		return nil, err
	}

	for i := range emitted {
		if emitted[i].Index == dealerIndex {
			return types.ConvertToRespProto(&emitted[i]), nil
		}
	}

	return nil, nil
}

func validateProcessDealsRequest(req *pb.ProcessDealsRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	if len(req.GetDeals()) == 0 {
		return errors.New("empty deals to process")
	}

	return nil
}
