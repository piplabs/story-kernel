package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// registrationNetworkRetryAttempts/Delay bound how long GenerateAndSealKey waits for
	// the light client to observe the round's DKGNetwork at a round boundary. The verified
	// head has been observed to trail the chain tip by ~40s when a round starts, so the
	// budget (30 x 3s = 90s) outlasts that with margin.
	registrationNetworkRetryAttempts = 30
	registrationNetworkRetryDelay    = 3 * time.Second

	// registrationLagNormalAttempts is how many retry attempts fall within the ~40s lag
	// documented above. Within it a not-found read is expected steady-state behavior and
	// logs at Debug; beyond it the wait is abnormal and escalates to Warn.
	registrationLagNormalAttempts = 15
)

func (s *DKGServer) GenerateAndSealKey(ctx context.Context, req *pb.GenerateAndSealKeyRequest) (*pb.GenerateAndSealKeyResponse, error) {
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

	// Only fetch the DKG network (not registrations) since no registrations
	// exist yet at key generation time.
	network, err := s.waitForDKGNetworkCreation(ctx, codeCommitmentHex, req.Round,
		registrationNetworkRetryAttempts, registrationNetworkRetryDelay)
	if err != nil {
		// A canceled request is the caller going away, not a server failure.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.WithFields(log.Fields{
				"round":           req.Round,
				"code_commitment": codeCommitmentHex,
			}).Warnf("GenerateAndSealKey aborted while waiting for DKG network: %v", err)

			return nil, status.FromContextError(err).Err()
		}

		log.WithFields(log.Fields{
			"round":           req.Round,
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get DKG network: %v", err)

		if errors.Is(err, ErrLightClientLag) {
			return nil, status.Errorf(codes.Unavailable, "DKG network not yet visible to the light client")
		}

		return nil, status.Errorf(codes.Internal, "failed to get DKG network")
	}

	// Verify the DKG start block is on the canonical chain.
	// This ensures the DKG round was legitimately initiated on-chain before generating keys.
	if err := s.verifyDKGStartBlock(ctx, network); err != nil {
		// A canceled request is the caller going away, not a verification failure.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.WithFields(log.Fields{
				"round":           req.Round,
				"code_commitment": codeCommitmentHex,
			}).Warnf("GenerateAndSealKey aborted during start block verification: %v", err)

			return nil, status.FromContextError(err).Err()
		}

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

	// Generate (or load) the key pairs only after the round is proven to exist on the
	// canonical chain, so requests for bogus rounds cannot mint sealed key files.
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

	log.Info("Key pairs are successfully generated and sealed or loaded from the existing key files")

	reportData, err := calculateReportData(
		req.Address,
		req.Round,
		uint64(network.StartBlockHeight),
		network.StartBlockHash,
		edPubBz,                           // dkgPubKey
		ecrypto.FromECDSAPub(secpPub)[1:], // enclaveCommKey
	)
	if err != nil {
		log.WithFields(log.Fields{
			"address":           req.Address,
			"round":             req.Round,
			"ed25519_pub_key":   hex.EncodeToString(edPubBz),
			"secp256k1_pub_key": hex.EncodeToString(ecrypto.FromECDSAPub(secpPub)),
		}).Errorf("failed to calculate report data: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to calculate report data")
	}

	// Generate TEE remote attestation evidence binding reportData. The
	// active backend chooses the wire format: SGX returns raw EREPORT
	// bytes (Gramine /dev/attestation); TDX returns a raw V4 quote with
	// reportData padded into V4.report_data. Caller is backend-agnostic.
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

// waitForDKGNetworkCreation blocks until the round's on-chain DKGNetwork record becomes
// visible at the light client's verified height, then returns it. The consensus client only
// requests key generation for a round it observed on-chain, so a not-found read here is
// presumed to be light-client lag rather than a nonexistent round; any other error fails
// fast. Returns ErrLightClientLag once the retry budget is exhausted, or ctx.Err() if the
// caller goes away mid-wait.
func (s *DKGServer) waitForDKGNetworkCreation(
	ctx context.Context,
	codeCommitmentHex string,
	round uint32,
	attempts int,
	delay time.Duration,
) (*pb.DKGNetwork, error) {
	for attempt := range attempts {
		network, err := s.QueryClient.GetDKGNetwork(ctx, codeCommitmentHex, round)
		if err == nil {
			return network, nil
		}

		if !errors.Is(err, story.ErrDKGNetworkNotFound) {
			return nil, err
		}

		if attempt+1 == attempts {
			break
		}

		fields := log.Fields{"round": round, "attempt": attempt + 1}
		msg := "GenerateAndSealKey: DKG network not yet visible to light client, retrying"
		if attempt+1 > registrationLagNormalAttempts {
			log.WithFields(fields).Warn(msg)
		} else {
			log.WithFields(fields).Debug(msg)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	return nil, fmt.Errorf("%w: round %d DKG network not visible after %d attempts",
		ErrLightClientLag, round, attempts)
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
