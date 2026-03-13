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

		return nil, status.Errorf(codes.Internal, "failed to validate code commitment")
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	// Load DKG state from cache or rebuild from state
	var distKeyGen *dkg.DistKeyGenerator
	if !req.GetIsResharing() {
		distKeyGen, err = s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild initial distributed key generator: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial distributed key generator")
		}
	} else {
		distKeyGen, err = s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the distributed key generator for resharing: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild the distributed key generator for resharing")
		}
	}

	// Debug: log verifier state BEFORE processing deals
	verifiersBefore := distKeyGen.Verifiers()
	log.WithFields(log.Fields{
		"round":           req.GetRound(),
		"code_commitment": codeCommitmentHex,
		"num_verifiers":   len(verifiersBefore),
		"num_deals_in":    len(req.GetDeals()),
		"is_resharing":    req.GetIsResharing(),
	}).Info("ProcessDeals: verifier state BEFORE processing")

	var (
		pbResps []*pb.Response
		deals   []dkg.Deal
	)
	for _, d := range req.GetDeals() {
		deal := types.ConvertToDeal(d)
		resp, err := distKeyGen.ProcessDeal(deal)
		if err != nil {
			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
				"sender_index":    deal.Index,
			}).Errorf("failed to process the deal: %v", err)

			continue
		}

		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"dealer_index":    deal.Index,
			"resp_status":     resp.Response.Status,
		}).Info("ProcessDeals: deal processed successfully")

		pbResp := types.ConvertToRespProto(resp)
		pbResps = append(pbResps, pbResp)
		deals = append(deals, *deal)
	}

	// Debug: log verifier state AFTER processing deals
	verifiersAfter := distKeyGen.Verifiers()
	for idx, v := range verifiersAfter {
		deal := v.Deal()
		commitLen := 0
		if deal != nil {
			commitLen = len(deal.Commitments)
		}
		log.WithFields(log.Fields{
			"round":          req.GetRound(),
			"verifier_idx":   idx,
			"has_deal":       deal != nil,
			"commitment_len": commitLen,
			"deal_certified": v.DealCertified(),
		}).Info("ProcessDeals: verifier state AFTER processing")
	}

	if err := s.DKGStore.AddDeals(codeCommitmentHex, req.GetRound(), deals); err != nil {
		log.Errorf("failed to add deals to the DKG state: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to add deals to the DKG state")
	}

	log.WithFields(log.Fields{
		"code_commitment": codeCommitmentHex,
		"round":           req.GetRound(),
		"deals_applied":   len(deals),
		"responses_out":   len(pbResps),
	}).Info("All deals have been processed")

	return &pb.ProcessDealsResponse{
		CodeCommitment: req.GetCodeCommitment(),
		Round:          req.GetRound(),
		Responses:      pbResps,
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
