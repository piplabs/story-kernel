package service

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
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

// ProcessDeals process the deals. It is assumed that the deal has been correctly delivered to the corresponding recipient index.
func (s *DKGServer) ProcessDeals(_ context.Context, req *pb.ProcessDealsRequest) (*pb.ProcessDealsResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessDealsRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"num_deals":       len(req.GetDeals()),
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

	// dealerCount upper-bounds Deal.Index. Non-resharing has a single
	// committee acting as dealers; resharing dealers are members of the
	// PRIOR active committee (kyber's c.OldNodes inside the next-DKG).
	var (
		distKeyGen  *dkg.DistKeyGenerator
		dealerCount int
	)
	if !req.GetIsResharing() {
		dealerCount = len(rc.SortedPubKeys)

		distKeyGen, err = s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild initial distributed key generator: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial distributed key generator")
		}
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			log.Errorf("failed to get the latest active round of DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to get the latest active round of DKG")
		}
		if latest == nil || latest.GetTotal() == 0 {
			return nil, status.Errorf(codes.FailedPrecondition,
				"resharing requires an active prior DKG network")
		}
		dealerCount = int(latest.GetTotal())

		distKeyGen, err = s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the distributed key generator for resharing: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild the distributed key generator for resharing")
		}
	}

	var (
		pbResps  []*pb.Response
		deals    []dkg.Deal
		rejected []*pb.Deal
	)
	for _, d := range req.GetDeals() {
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
		if err != nil {
			// Idempotent re-submission: the cached DistKeyGenerator has already
			// absorbed this deal. Silent skip — do NOT include in rejected_deals
			// so the client does not retry an artifact kyber will keep rejecting.
			if isAlreadyProcessedErr(err) {
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
					"sender_index":    deal.Index,
				}).Debugf("deal already stored on cached generator; skipping silently: %v", err)

				continue
			}

			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
				"sender_index":    deal.Index,
			}).Errorf("failed to process the deal: %v", err)

			rejected = append(rejected, d)

			continue
		}

		pbResp := types.ConvertToRespProto(resp)
		pbResps = append(pbResps, pbResp)
		deals = append(deals, *deal)
	}

	if len(deals) > 0 {
		if err := s.DKGStore.AddDeals(codeCommitmentHex, req.GetRound(), deals); err != nil {
			log.Errorf("failed to add deals to the DKG state: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to add deals to the DKG state")
		}
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"processed":       len(deals),
		"rejected":        len(rejected),
	}).Info("Processed deals")

	return &pb.ProcessDealsResponse{
		CodeCommitment: req.GetCodeCommitment(),
		Round:          req.GetRound(),
		Responses:      pbResps,
		RejectedDeals:  rejected,
	}, nil
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
