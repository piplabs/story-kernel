package service

import (
	"context"
	"encoding/hex"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *DKGServer) GenerateAndSealKey(_ context.Context, req *pb.GenerateAndSealKeyRequest) (*pb.GenerateAndSealKeyResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate the request
	if err := validateGenerateAndSealKeyRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"address":         req.GetAddress(),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request")
	}

	// Compare the code commitment
	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("invalid code commitment: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "failed to validate code commitment")
	}

	_, edPub, err := s.DKGStore.LoadOrGenerateEd25519Key(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to load or generate Ed25519 key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load or generate Ed25519 key")
	}

	edPubBz, err := edPub.MarshalBinary()
	if err != nil {
		log.Errorf("failed to marshal the Ed25519 public key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal the Ed25519 public key")
	}

	_, secpPub, err := s.DKGStore.LoadOrGenerateSecp256k1Key(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to load or generate Secp256k1 key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load or generate Secp256k1 key")
	}

	// Debug: log derived address from generated/loaded secp256k1 key for diagnosing commPubKey mismatch
	commPubKeyBytes := ecrypto.FromECDSAPub(secpPub)[1:]
	derivedAddr := ecrypto.Keccak256(commPubKeyBytes)[12:]
	log.WithFields(log.Fields{
		"round":            req.Round,
		"code_commitment":  codeCommitmentHex,
		"comm_pub_key_hex": hex.EncodeToString(commPubKeyBytes),
		"derived_address":  hex.EncodeToString(derivedAddr),
		"key_path":         s.DKGStore.Secp256k1KeyPath(codeCommitmentHex, req.GetRound()),
	}).Info("Key pairs are successfully generated and sealed or loaded from the existing key files")

	// Only fetch the DKG network (not registrations) since no registrations
	// exist yet at key generation time.
	network, err := s.QueryClient.GetDKGNetwork(context.Background(), codeCommitmentHex, req.Round)
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.Round,
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get DKG network: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get DKG network")
	}

	// Verify the DKG start block is on the canonical chain.
	// This ensures the DKG round was legitimately initiated on-chain before generating keys.
	if err := s.verifyDKGStartBlock(context.Background(), network); err != nil {
		log.WithFields(log.Fields{
			"round":              req.Round,
			"code_commitment":    codeCommitmentHex,
			"start_block_height": network.StartBlockHeight,
			"start_block_hash":   hex.EncodeToString(network.StartBlockHash),
			"error":              err.Error(),
		}).Errorf("DKG start block verification failed")

		return nil, status.Errorf(codes.FailedPrecondition,
			"start block verification failed at height %d: %v",
			network.StartBlockHeight, err)
	}

	// Generate a quote with start block information included in report data.
	// report data := hash(validatorAddress, round, edPub, secpPub, startBlockHeight, startBlockHash)
	// This anchors the attestation to a specific blockchain state that will be verified on-chain.
	reportData, err := calculateReportData(
		req.Address,
		req.Round,
		edPubBz,
		ecrypto.FromECDSAPub(secpPub)[1:],
		network.StartBlockHeight,
		network.StartBlockHash,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"address":            req.Address,
			"round":              req.Round,
			"ed25519_pub_key":    hex.EncodeToString(edPubBz),
			"secp256k1_pub_key":  hex.EncodeToString(ecrypto.FromECDSAPub(secpPub)),
			"start_block_height": network.StartBlockHeight,
			"start_block_hash":   hex.EncodeToString(network.StartBlockHash),
		}).Errorf("failed to calculate report data: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to calculate report data")
	}

	// Generate SGX quote using Gramine's /dev/attestation interface
	rawQuote, err := enclave.GetRemoteQuote(reportData)
	if err != nil {
		log.Errorf("failed to generate quote: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to generate quote")
	}

	log.Info("Raw quote is successfully generated")

	return &pb.GenerateAndSealKeyResponse{
		Round:            req.GetRound(),
		CodeCommitment:   req.GetCodeCommitment(),
		DkgPubKey:        edPubBz,
		CommPubKey:       ecrypto.FromECDSAPub(secpPub)[1:],
		EnclaveReport:    rawQuote,
		StartBlockHeight: network.StartBlockHeight,
		StartBlockHash:   network.StartBlockHash,
	}, nil
}

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
