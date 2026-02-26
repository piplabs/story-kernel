package service

import (
	"github.com/pkg/errors"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func validateGenerateAndSealKeyRequest(req *pb.GenerateAndSealKeyRequest) error {
	if len(req.GetAddress()) == 0 {
		return errors.New("validator address is required but missing")
	}

	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	return nil
}
