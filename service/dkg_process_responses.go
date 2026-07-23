package service

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
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
	var (
		justifications []*pb.Justification
		resps          []dkg.Response
		rejected       []*pb.Response
	)

	// Serialize the shared DistKeyGenerator mutation with the other DKG-mutating
	// RPCs for this round (see dkgMutationMu). Persist runs after the loop under
	// its own store lock, so only the kyber mutation needs covering here.
	mu := s.getDKGMutationMu(req.GetRound())
	mu.Lock()
	for _, response := range req.GetResponses() {
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

		// processed: at least one DistKeyGenerator applied the response (real
		// success or idempotent re-submission). In resharing (prev + next),
		// only one generator typically owns a given response — the others
		// may return real errors ("unknown dealer" etc.) without indicating
		// rejection. Reject only when EVERY generator returned a real
		// (non-idempotent) error.
		processed := false
		for _, distKeyGen := range distKeyGens {
			j, err := distKeyGen.ProcessResponse(resp)
			if err != nil {
				// Log only indices to match the dealing/justification handlers'
				// hygiene; avoids dumping the full VSSResponse struct into logs
				// in case future kyber/proto evolution adds fields not safe to
				// expose verbatim.
				log.WithFields(log.Fields{
					"round":            req.GetRound(),
					"code_commitment":  codeCommitmentHex,
					"dealer_index":     response.GetIndex(),
					"complainer_index": response.GetVssResponse().GetIndex(),
				}).Errorf("failed to process the response: %v", err)

				if isAlreadyProcessedErr(err) {
					processed = true
				}

				continue
			}

			processed = true

			if j == nil {
				continue
			}

			justification, convErr := types.ConvertToJustificationProto(j)
			if convErr != nil {
				// kyber already absorbed `resp`; retry would hit the idempotent
				// guard (j == nil) and never re-derive the justification.
				// Putting `response` in rejected_responses would mislead the CL
				// into retrying a permanently-lost artifact, and failing the
				// whole RPC would also discard valid justifications already
				// converted in this batch. Drop only this justification — the
				// response itself is still added to resps below so kyber's
				// in-memory state and DKGStore stay consistent.
				// (Effectively unreachable on Ed25519 — kept for future suite changes.)
				// Log only the index to avoid leaking SecShare from PlainDeal.
				log.WithFields(log.Fields{
					"round":               req.GetRound(),
					"code_commitment":     codeCommitmentHex,
					"justification_index": j.Index,
				}).Errorf("failed to convert generated justification to proto; "+
					"justification dropped: %v", convErr)

				continue
			}

			justifications = append(justifications, justification)
		}

		if !processed {
			rejected = append(rejected, response)

			continue
		}

		resps = append(resps, *resp)
	}
	mu.Unlock()

	if len(resps) > 0 {
		if err := s.DKGStore.AddResponses(codeCommitmentHex, req.GetRound(), resps); err != nil {
			log.Errorf("failed to add responses to the DKG state: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to add responses to the DKG state")
		}
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"processed":       len(resps),
		"rejected":        len(rejected),
	}).Info("Processed responses")

	return &pb.ProcessResponsesResponse{
		Justifications:    justifications,
		RejectedResponses: rejected,
	}, nil
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
