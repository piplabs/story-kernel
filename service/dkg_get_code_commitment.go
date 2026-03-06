package service

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetCodeCommitment returns the code commitment (MRENCLAVE) of this story-kernel instance.
// This allows the CL client to discover which enclave build it is communicating with
// without needing to supply or know the code commitment in advance.
func (s *DKGServer) GetCodeCommitment(_ context.Context, _ *pb.GetCodeCommitmentRequest) (*pb.GetCodeCommitmentResponse, error) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	if err != nil {
		log.Errorf("failed to get self code commitment: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get self code commitment")
	}

	return &pb.GetCodeCommitmentResponse{
		CodeCommitment: codeCommitment,
	}, nil
}
