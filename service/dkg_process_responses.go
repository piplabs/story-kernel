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

		return nil, status.Errorf(codes.Internal, "invalid request")
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

	// Process the responses
	var (
		justifications []*pb.Justification
		resps          []dkg.Response
	)
	for _, response := range req.GetResponses() {
		resp := types.ConvertToVSSResp(response)
		for _, distKeyGen := range distKeyGens {
			j, err := distKeyGen.ProcessResponse(resp)
			if err != nil {
				// skip the responses
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
					"index":           response.GetIndex(),
					"vss_response":    response.GetVssResponse(),
				}).Errorf("failed to process the response: %v", err)

				continue
			}

			if j != nil {
				justification, err := types.ConvertToJustificationProto(j)
				if err != nil {
					log.WithFields(log.Fields{
						"index":         j.Index,
						"justification": j.Justification,
					}).Errorf("failed to convert to justification proto: %v", err)

					return nil, status.Errorf(codes.Internal, "failed to convert to justification proto")
				}

				justifications = append(justifications, justification)
			}
		}

		resps = append(resps, *resp)
	}

	if err := s.DKGStore.AddResponses(codeCommitmentHex, req.GetRound(), resps); err != nil {
		log.Errorf("failed to add responses to the DKG state: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to add responses to the DKG state")
	}

	log.Info("All responses have been processed", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	return &pb.ProcessResponsesResponse{
		Justifications: justifications,
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
