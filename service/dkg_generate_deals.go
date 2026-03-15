package service

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
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

	// For resharing rounds, skip CachePID because:
	// 1. The dealer's identity is resolved through longterm key matching in the kyber DKG
	//    library (dkg.Config.Longterm vs OldNodes), not through the PID cache.
	// 2. During upgrade resharing, the current round's key is sealed by the new binary's
	//    enclave, making it inaccessible from the old binary that generates deals.
	// 3. PIDCache is only consumed by PartialDecryptTDH2, which receives PID in its request.
	if !req.GetIsResharing() {
		if err := s.CachePID(codeCommitmentHex, req.Round, rc.Registrations); err != nil {
			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
			}).Errorf("failed to cache PID: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to cache PID")
		}
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

	// DEBUG: corrupt first deal's cipher and re-sign at DKG level.
	// Outer Schnorr passes, inner AEAD decryption produces garbage → VerifyDeal fails → complaint.
	if s.Cfg.TestCorruptDeal {
		if err := corruptFirstDeal(s, deals, codeCommitmentHex, req.GetRound()); err != nil {
			log.Warnf("[DEBUG] Failed to corrupt deal: %v", err)
		}
	}

	log.Info("Succeed to generate deals", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	// Set deals into response
	resp := createGenerateDealsResponse(req.GetRound(), req.GetCodeCommitment(), deals)

	return resp, nil
}

// corruptFirstDeal corrupts one deal's cipher and re-signs at DKG level.
// Outer Schnorr passes but inner AEAD decryption produces garbage →
// VerifyDeal fails → StatusComplaint. DEBUG ONLY.
func corruptFirstDeal(s *DKGServer, deals map[int]*dkg.Deal, ccHex string, round uint32) error {
	for idx, deal := range deals {
		if len(deal.Deal.Cipher) == 0 {
			continue
		}

		// Corrupt cipher
		for i := 0; i < 8 && i < len(deal.Deal.Cipher); i++ {
			deal.Deal.Cipher[i] ^= 0xFF
		}

		// Re-sign at DKG level so outer signature check passes
		longterm, err := s.DKGStore.LoadSealedEd25519Key(ccHex, round)
		if err != nil {
			return errors.Wrap(err, "load longterm key for re-signing")
		}

		buff, err := deal.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, "marshal corrupted deal")
		}

		deal.Signature, err = schnorr.Sign(s.Suite, longterm, buff)
		if err != nil {
			return errors.Wrap(err, "re-sign corrupted deal")
		}

		log.Warnf("[DEBUG] Corrupted deal cipher and re-signed: recipient_index=%d round=%d", idx, round)

		return nil
	}

	return nil
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
		return errors.New("own public key not found in registrations")
	}

	s.PIDCache.Set(round, ownPID)

	return nil
}
