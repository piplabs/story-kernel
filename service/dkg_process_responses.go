package service

import (
	"github.com/pkg/errors"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

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
