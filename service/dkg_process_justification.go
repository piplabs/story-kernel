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

// ProcessJustification takes valid justifications from the CL and calls kyber's
// DistKeyGenerator.ProcessJustification() for each to restore the DKG state for
// the originally-complained deals. This is only called when the CL has already
// verified each justification via Pedersen VSS verification.
func (s *DKGServer) ProcessJustification(_ context.Context, req *pb.ProcessJustificationRequest) (*pb.ProcessJustificationResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessJustificationRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
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

	// Get the appropriate DistKeyGenerator(s) based on whether this is a resharing round.
	// For resharing, justifications must be processed through both prev and next DKGs
	// (same pattern as ProcessResponses).
	var distKeyGens []*dkg.DistKeyGenerator
	if !req.GetIsResharing() {
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

		prevDistKeyGen, err := s.GetResharingPrevDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys, latest)
		if err != nil {
			log.Infof("failed to load or rebuild the previous distributed key generator for resharing, skip processing justifications for the previous distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, prevDistKeyGen)
		}

		nextDistKeyGen, err := s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the next distributed key generator for resharing, skip processing justifications for the next distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, nextDistKeyGen)
		}
	}

	// Process each justification through all DKG instances, continuing on
	// individual failures (matches ProcessDeals/ProcessResponses pattern).
	var processed []dkg.Justification
	for _, j := range req.GetJustifications() {
		justification, err := types.ConvertToJustification(j)
		if err != nil {
			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
			}).Errorf("failed to convert justification from proto: %v", err)

			continue
		}

		for _, distKeyGen := range distKeyGens {
			if err := distKeyGen.ProcessJustification(justification); err != nil {
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
					"dealer_index":    justification.Index,
				}).Errorf("failed to process justification: %v", err)

				continue
			}
		}

		processed = append(processed, *justification)

		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"dealer_index":    justification.Index,
		}).Info("Justification processed successfully, DKG state restored for the deal")
	}

	// Persist successfully processed justifications for recovery replay
	if len(processed) > 0 {
		if err := s.DKGStore.AddJustifications(codeCommitmentHex, req.GetRound(), processed); err != nil {
			log.Errorf("failed to add justifications to the DKG state: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to add justifications to the DKG state")
		}
	}

	log.Info("All justifications have been processed", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	return &pb.ProcessJustificationResponse{}, nil
}

func validateProcessJustificationRequest(req *pb.ProcessJustificationRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	if len(req.GetJustifications()) == 0 {
		return errors.New("justifications are required but missing")
	}

	return nil
}
