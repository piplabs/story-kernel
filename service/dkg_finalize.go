package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// finalizeStageRetryAttempts/Delay bound how long FinalizeDKG waits for the light
	// client to reach the finalization stage. The light client refreshes every 3s, so a
	// 2s interval observes the update promptly; 5 attempts (~10s) covers observed lag.
	finalizeStageRetryAttempts = 5
	finalizeStageRetryDelay    = 2 * time.Second
)

func (s *DKGServer) FinalizeDKG(_ context.Context, req *pb.FinalizeDKGRequest) (*pb.FinalizeDKGResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateFinalizeDKGRequest(req); err != nil {
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

	// Calculate participants root from the post-invalidation participant set. The chain
	// flips the round to the finalization stage, invalidates dealers that submitted no deal,
	// and emits BeginDKGFinalization in the same block, so we must wait until the light
	// client has observed that block before reading registrations. Otherwise a lagging
	// trusted height may still report an invalidated dealer as VERIFIED, producing a
	// participants root that disagrees with the set the chain agreed on.
	//
	// Snapshotting the share only after this wait also lets more of the response feed drain,
	// so DistKeyShare() interpolates over a fuller QUAL; that same share is sealed and later
	// used for dealing (loadFromRoundShare), keeping deals and on-chain coeffs consistent.
	registrations, err := s.waitForFinalizationRegistrations(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to get finalization DKG registrations: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get finalization DKG registrations")
	}

	participantsRoot, err := calculateParticipantsRoot(registrations)
	if err != nil {
		log.Errorf("failed to calculate participants root: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to calculate participants root")
	}

	// Enable the timeout so DealCertified tolerates up to n-t absent verifier responses,
	// restoring the configured threshold's fault tolerance; without it a single absent
	// verifier fails the whole round. SetTimeout propagates to every verifier's aggregator.
	distKeyGen.SetTimeout()

	// Generate Distributed Key Share
	distKeyShare, err := distKeyGen.DistKeyShare()
	if err != nil {
		log.Errorf("failed to compute distributed key share: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to compute distributed key share")
	}
	if distKeyShare == nil {
		log.Errorf("distributed key share is nil")

		return nil, status.Errorf(codes.Internal, "distributed key share is nil")
	}
	priShare := distKeyShare.PriShare()
	if priShare == nil || priShare.V == nil {
		log.Errorf("distributed key private share is nil")

		return nil, status.Errorf(codes.Internal, "distributed key private share is nil")
	}

	log.Info("Distributed key share has been generated", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	pubKeyShare, err := marshalPubShare(priShare.V)
	if err != nil {
		log.Errorf("failed to marshal public key share: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal public key share")
	}

	// Seal and store the DistKeyShare
	if err := s.DKGStore.SealAndStoreDistKeyShare(distKeyShare, codeCommitmentHex, req.GetRound()); err != nil {
		log.Errorf("failed to seal distributed key share: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to seal distributed key")
	}

	// Caching the dist key share
	s.DistKeyShareCache.Set(req.GetRound(), distKeyShare)

	// Get the global public key
	globalPubKey, err := distKeyShare.Public().MarshalBinary()
	if err != nil {
		log.Errorf("failed to marshal global public key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal global public key")
	}

	publicCoeffsBz, err := MarshalPoints(distKeyShare.Commits)
	if err != nil {
		log.Errorf("failed to marshal public coeffs: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal public coeffs")
	}

	// Hash response message
	respHash, err := hashFinalizeDKGResponse(req.GetCodeCommitment(), req.GetRound(), participantsRoot, globalPubKey, publicCoeffsBz, pubKeyShare)
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"global_pub_key":  hex.EncodeToString(globalPubKey),
		}).Errorf("failed to hash response message: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to hash response")
	}

	// Load sealed secp256k1 key and sign the hash
	priv, err := s.DKGStore.LoadSealedSecp256k1Key(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to load sealed Secp256k1 private key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load sealed secp256k1 key")
	}
	// Zero out the private key after use to minimize exposure in memory.
	defer zeroPrivateKey(priv)

	signature, err := ecrypto.Sign(respHash, priv)
	if err != nil {
		log.Errorf("failed to sign on the response message: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to sign on the response message")
	}
	if signature[64] < 27 {
		signature[64] += 27
	}

	// Construct response
	return &pb.FinalizeDKGResponse{
		CodeCommitment:   req.GetCodeCommitment(),
		Round:            req.GetRound(),
		ParticipantsRoot: participantsRoot[:],
		GlobalPubKey:     globalPubKey,
		PublicCoeffs:     publicCoeffsBz,
		PubKeyShare:      pubKeyShare,
		Signature:        signature,
	}, nil
}

func validateFinalizeDKGRequest(req *pb.FinalizeDKGRequest) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	return nil
}

// waitForFinalizationRegistrations blocks until the light client observes the round at the
// finalization stage (or later), then returns the participant registrations read at that
// height. Because missing-dealer invalidation happens in the same block that advances the
// stage to finalization, waiting for that stage guarantees the returned set excludes any
// invalidated dealer, so the kernel's participants root matches the chain's. It retries
// while the light client still reports an earlier stage, returning ErrLightClientLag once
// the retry budget is exhausted.
func (s *DKGServer) waitForFinalizationRegistrations(codeCommitmentHex string, round uint32) ([]*pb.DKGRegistration, error) {
	for attempt := range finalizeStageRetryAttempts {
		network, err := s.QueryClient.GetDKGNetwork(context.Background(), codeCommitmentHex, round)
		if err != nil {
			return nil, err
		}

		if network.GetStage() >= pb.DKGStage_DKG_STAGE_FINALIZATION {
			return s.QueryClient.GetAllParticipantDKGRegistrations(context.Background(), codeCommitmentHex, round)
		}

		log.WithFields(log.Fields{
			"round":   round,
			"stage":   network.GetStage().String(),
			"attempt": attempt + 1,
		}).Warn("FinalizeDKG: light client has not observed the finalization stage yet, retrying")

		time.Sleep(finalizeStageRetryDelay)
	}

	return nil, fmt.Errorf("%w: round %d did not reach finalization stage after %d retries",
		ErrLightClientLag, round, finalizeStageRetryAttempts)
}

// This matches the validation logic in the Story blockchain DKG module.
func calculateParticipantsRoot(registrations []*pb.DKGRegistration) ([32]byte, error) {
	if len(registrations) == 0 {
		return [32]byte{}, errors.New("no registrations provided")
	}

	// Extract and validate addresses
	addrs := make([]string, 0, len(registrations))
	for _, reg := range registrations {
		addr := strings.ToLower(strings.TrimSpace(reg.GetValidatorAddr()))
		if !common.IsHexAddress(addr) {
			return [32]byte{}, errors.Errorf("invalid validator evm address: %s", reg.GetValidatorAddr())
		}
		addrs = append(addrs, addr)
	}

	// Sort addresses
	slices.Sort(addrs)

	// Concatenate address bytes
	buf := make([]byte, 0, common.AddressLength*len(addrs))
	for _, a := range addrs {
		evmAddr := common.HexToAddress(a)
		buf = append(buf, evmAddr.Bytes()...)
	}

	// Calculate Keccak256 hash
	hash := ecrypto.Keccak256Hash(buf)

	return hash, nil
}
