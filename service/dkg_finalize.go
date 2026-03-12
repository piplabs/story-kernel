package service

import (
	"context"
	"encoding/hex"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *DKGServer) FinalizeDKG(_ context.Context, req *pb.FinalizeDKGRequest) (resp *pb.FinalizeDKGResponse, err error) {
	// Recover from panics in the kyber DKG library (e.g., index out of range
	// in resharingKey) to prevent the gRPC server from crashing.
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic in FinalizeDKG: %v\nstack trace:\n%s", r, debug.Stack())
			resp = nil
			err = status.Errorf(codes.Internal, "internal panic during FinalizeDKG: %v", r)
		}
	}()

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

	// DEBUG: Log DKG handler state before calling DistKeyShare
	log.WithFields(log.Fields{
		"round":           req.GetRound(),
		"code_commitment": codeCommitmentHex,
		"is_resharing":    req.GetIsResharing(),
		"verifiers_count": len(distKeyGen.Verifiers()),
		"qual":            distKeyGen.QUAL(),
	}).Info("DEBUG: DKG handler state before DistKeyShare")

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

	pubKeyShare, err := s.Suite.Point().Mul(priShare.V, nil).MarshalBinary()
	if err != nil {
		log.Errorf("failed to marshal public key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal public key")
	}

	// Seal and store the DistKeyShare
	if err := store.SealAndStoreDistKeyShare(distKeyShare, s.Cfg.GetDKGStateDir(), codeCommitmentHex, req.GetRound()); err != nil {
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

	// Calculate participants root from verified registrations
	registrations, err := s.QueryClient.GetAllParticipantDKGRegistrations(context.Background(), codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to get verified DKG registrations: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get verified DKG registrations")
	}

	participantsRoot, err := calculateParticipantsRoot(registrations)
	if err != nil {
		log.Errorf("failed to calculate participants root: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to calculate participants root")
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
	keyPath := s.DKGStore.Secp256k1KeyPath(codeCommitmentHex, req.GetRound())
	priv, err := s.DKGStore.LoadSealedSecp256k1Key(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"key_path":        keyPath,
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to load sealed Secp256k1 private key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load sealed secp256k1 key")
	}
	// Zero out the private key after use to minimize exposure in memory.
	defer zeroPrivateKey(priv)

	// Debug: log the address derived from the loaded key for diagnosing commPubKey mismatch
	loadedPub := ecrypto.FromECDSAPub(&priv.PublicKey)[1:]
	loadedAddr := ecrypto.Keccak256(loadedPub)[12:]
	log.WithFields(log.Fields{
		"round":               req.GetRound(),
		"code_commitment":     codeCommitmentHex,
		"key_path":            keyPath,
		"loaded_comm_pub_key": hex.EncodeToString(loadedPub),
		"loaded_derived_addr": hex.EncodeToString(loadedAddr),
		"participants_root":   hex.EncodeToString(participantsRoot[:]),
		"global_pub_key":      hex.EncodeToString(globalPubKey),
		"pub_key_share":       hex.EncodeToString(pubKeyShare),
		"resp_hash":           hex.EncodeToString(respHash),
	}).Info("DEBUG: FinalizeDKG loaded sealed key and computed response hash")

	signature, err := ecrypto.Sign(respHash, priv)
	if err != nil {
		log.Errorf("failed to sign on the response message: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to sign on the response message")
	}
	if signature[64] < 27 {
		signature[64] += 27
	}

	// Debug: self-verify the signature to catch mismatches before sending
	selfVerifySig := make([]byte, 65)
	copy(selfVerifySig, signature)
	if selfVerifySig[64] >= 27 {
		selfVerifySig[64] -= 27
	}
	recoveredPub, recoverErr := ecrypto.SigToPub(respHash, selfVerifySig)
	if recoverErr != nil {
		log.WithFields(log.Fields{
			"round": req.GetRound(),
			"error": recoverErr.Error(),
		}).Error("DEBUG: failed to self-verify finalization signature")
	} else {
		recoveredPubBytes := ecrypto.FromECDSAPub(recoveredPub)[1:]
		recoveredAddrBytes := ecrypto.Keccak256(recoveredPubBytes)[12:]
		sigMatch := hex.EncodeToString(loadedAddr) == hex.EncodeToString(recoveredAddrBytes)
		log.WithFields(log.Fields{
			"round":             req.GetRound(),
			"loaded_addr":       hex.EncodeToString(loadedAddr),
			"recovered_addr":    hex.EncodeToString(recoveredAddrBytes),
			"signature_matches": sigMatch,
		}).Info("DEBUG: FinalizeDKG self-verification result")
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
