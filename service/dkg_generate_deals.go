package service

import (
	"bytes"
	"context"

	"github.com/pkg/errors"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

func validateGenerateDealsRequest(req *pb.GenerateDealsRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	return nil
}

// verifyDKGStartBlock verifies that the DKG round's start block is on the canonical chain.
func (s *DKGServer) verifyDKGStartBlock(ctx context.Context, network *pb.DKGNetwork) error {
	return s.QueryClient.VerifyStartBlock(ctx, network.GetStartBlockHeight(), network.GetStartBlockHash())
}

func (s *DKGServer) CachePID(codeCommitmentHex string, round uint32, regs []*pb.DKGRegistration) error {
	// Find the story-kernel's own registration by matching pubkey and use its Index as polynomial PID (1-based).
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
	if err != nil {
		return errors.Wrap(err, "failed to load sealed Ed25519 private key")
	}

	ownPubKey := s.Suite.Point().Mul(longterm, nil)
	ownPubKeyBytes, err := ownPubKey.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to marshal own public key")
	}

	var ownPID uint32
	for _, reg := range regs {
		if bytes.Equal(reg.GetDkgPubKey(), ownPubKeyBytes) {
			ownPID = reg.GetIndex()

			break
		}
	}

	if ownPID == 0 {
		return errors.Wrap(err, "own public key not found in registrations")
	}

	s.PIDCache.Set(round, ownPID)

	return nil
}
