package service

import (
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *DKGServer) GenerateDeals(_ context.Context, req *pb.GenerateDealsRequest) (*pb.GenerateDealsResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateGenerateDealsRequest(req); err != nil {
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

	// Best-effort PID caching: try to populate the PIDCache so that
	// PartialDecryptTDH2 can resolve this validator's polynomial index
	// without an extra sealed-key load. If it fails (e.g., sealed Ed25519
	// key not yet available during resharing), log a warning and continue.
	// PartialDecryptTDH2 has a lazy fallback (resolvePID) that will
	// compute the PID on-the-fly from the sealed key and registrations.
	if err := s.CachePID(codeCommitmentHex, req.Round, rc.Registrations); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"is_resharing":    req.GetIsResharing(),
		}).Warnf("failed to cache PID (PartialDecryptTDH2 will resolve lazily): %v", err)
	}

	// Load DKG state from cache or rebuild from state
	var distKeyGen *dkg.DistKeyGenerator
	if !req.GetIsResharing() {
		distKeyGen, err = s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to setup initial round DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial round DKG")
		}
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			log.Errorf("failed to get latest active DKG network: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to get latest active DKG network")
		}

		distKeyGen, err = s.GetResharingPrevDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys, latest)
		if err != nil {
			log.Errorf("failed to setup prev round DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild prev round DKG")
		}
	}

	// Generate deals
	deals, err := distKeyGen.Deals()
	if err != nil {
		log.Errorf("failed to generate encrypted deals: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to generate encrypted deals")
	}

	// Persist dealer polynomial coefficients for restart recovery.
	// If GenerateDeals succeeds but the kernel restarts before FinalizeDKG,
	// the rebuild functions (rebuildInitDKG, rebuildResharingPrevDKG) need the
	// original polynomial to restore the dealer state (session ID, commitments)
	// correctly. Without this, a new random polynomial would be generated,
	// causing session ID mismatches with peers who already received the original
	// deals.
	//
	// This covers both initial and resharing rounds. In resharing, only the
	// secret coefficient (Share.V) is deterministic — the remaining t-1
	// polynomial coefficients are still random, producing different commitments
	// and session ID on each NewDistKeyHandler call.
	coeffs, extractErr := extractDealerPolyCoeffs(distKeyGen, s.Suite)
	if extractErr == nil && len(coeffs) > 0 {
		if persistErr := s.DKGStore.SetPrivateCoeffs(codeCommitmentHex, req.GetRound(), coeffs); persistErr != nil {
			log.Warnf("failed to persist dealer polynomial coefficients: %v", persistErr)
		}
	} else if extractErr != nil {
		log.Warnf("failed to extract dealer polynomial coefficients: %v", extractErr)
	}

	log.Info("Succeed to generate deals", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	// Set deals into response
	resp := createGenerateDealsResponse(req.GetRound(), req.GetCodeCommitment(), deals)

	return resp, nil
}

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
	pid, err := s.matchPIDFromRegistrations(codeCommitmentHex, round, regs)
	if err != nil {
		return err
	}

	s.PIDCache.Set(round, pid)

	return nil
}
