package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	"github.com/piplabs/story-kernel/types"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DKGServer struct {
	pb.UnsafeTEEServiceServer

	Cfg                *config.Config
	QueryClient        story.QueryClient
	Suite              *edwards25519.SuiteEd25519
	RoundCtxCache      *store.RoundContextCache
	InitDKGCache       *store.DKGCache
	ResharingPrevCache *store.ResharingCache
	ResharingNextCache *store.DKGCache
	DistKeyShareCache  *store.DistKeyShareCache
	DKGStore           *store.DKGStore
	PIDCache           *store.PIDCache
}

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

	log.Info("Key pairs are successfully generated and sealed or loaded from the existing key files")

	// Get round context to retrieve DKG network and start block information
	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.Round)
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.Round,
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	// Verify the DKG start block is on the canonical chain.
	// This ensures the DKG round was legitimately initiated on-chain before generating keys.
	if err := s.verifyDKGStartBlock(context.Background(), rc.Network); err != nil {
		log.WithFields(log.Fields{
			"round":              req.Round,
			"code_commitment":    codeCommitmentHex,
			"start_block_height": rc.Network.StartBlockHeight,
			"start_block_hash":   hex.EncodeToString(rc.Network.StartBlockHash),
			"error":              err.Error(),
		}).Errorf("DKG start block verification failed")

		return nil, status.Errorf(codes.FailedPrecondition,
			"start block verification failed at height %d: %v",
			rc.Network.StartBlockHeight, err)
	}

	// Generate a quote with start block information included in report data.
	// report data := hash(validatorAddress, round, edPub, secpPub, startBlockHeight, startBlockHash)
	// This anchors the attestation to a specific blockchain state that will be verified on-chain.
	reportData, err := calculateReportData(
		req.Address,
		req.Round,
		edPubBz,
		ecrypto.FromECDSAPub(secpPub)[1:],
		rc.Network.StartBlockHeight,
		rc.Network.StartBlockHash,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"address":            req.Address,
			"round":              req.Round,
			"ed25519_pub_key":    hex.EncodeToString(edPubBz),
			"secp256k1_pub_key":  hex.EncodeToString(ecrypto.FromECDSAPub(secpPub)),
			"start_block_height": rc.Network.StartBlockHeight,
			"start_block_hash":   hex.EncodeToString(rc.Network.StartBlockHash),
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
		RawQuote:         rawQuote,
		StartBlockHeight: rc.Network.StartBlockHeight,
		StartBlockHash:   rc.Network.StartBlockHash,
	}, nil
}

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

	if err := s.CachePID(codeCommitmentHex, req.Round, rc.Registrations); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to cache PID: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to cache PID")
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

	log.Info("Succeed to generate deals", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	// Set deals into response
	resp := createGenerateDealsResponse(req.GetRound(), req.GetCodeCommitment(), deals)

	return resp, nil
}

// ProcessDeals process the deals. It is assumed that the deal has been correctly delivered to the corresponding recipient index.
func (s *DKGServer) ProcessDeals(_ context.Context, req *pb.ProcessDealsRequest) (*pb.ProcessDealsResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessDealsRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"num_deals":       len(req.GetDeals()),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request")
	}

	// Validate code commitment
	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("failed to validate code commitment: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to validate code commitment")
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	// Load DKG state from cache or rebuild from state
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

	var (
		pbResps []*pb.Response
		deals   []dkg.Deal
	)
	for _, d := range req.GetDeals() {
		deal := types.ConvertToDeal(d)
		resp, err := distKeyGen.ProcessDeal(deal)
		if err != nil {
			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
				"sender_index":    deal.Index,
			}).Errorf("failed to process the deal: %v", err)

			continue
		}

		pbResp := types.ConvertToRespProto(resp)
		pbResps = append(pbResps, pbResp)
		deals = append(deals, *deal)
	}

	if err := s.DKGStore.AddDeals(codeCommitmentHex, req.GetRound(), deals); err != nil {
		log.Errorf("failed to add deals to the DKG state: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to add deals to the DKG state")
	}

	log.Info("All deals have been processed", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	return &pb.ProcessDealsResponse{
		CodeCommitment: req.GetCodeCommitment(),
		Round:          req.GetRound(),
		Responses:      pbResps,
	}, nil
}

func (s *DKGServer) ProcessResponses(_ context.Context, req *pb.ProcessResponsesRequest) (*pb.ProcessResponsesResponse, error) {
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Validate request
	if err := validateProcessResponsesRequest(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"num_responses":   len(req.GetResponses()),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.Internal, "invalid request")
	}

	// Validate code commitment
	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("failed to validate code commitment: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to validate code commitment")
	}

	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to get or load roundContext")
	}

	var distKeyGens []*dkg.DistKeyGenerator
	if !req.GetIsResharing() {
		distKeyGen, err := s.GetInitDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild initial distributed key generator: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load or rebuild initial distributed key generator")
		}
		distKeyGens = append(distKeyGens, distKeyGen)
	} else {
		latest, err := s.QueryClient.GetLatestActiveDKGNetwork(context.Background())
		if err != nil {
			log.Errorf("failed to get the latest active round of DKG: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to get the latest active round of DKG")
		}

		prevDistKeyGen, err := s.GetResharingPrevDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys, latest)
		if err != nil {
			log.Infof("failed to load or rebuild the previous distributed key generator for resharing, skip processing responses for the previous distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, prevDistKeyGen)
		}

		nextDistKeyGen, err := s.GetResharingNextDKG(codeCommitmentHex, req.GetRound(), rc.Network.GetThreshold(), rc.SortedPubKeys)
		if err != nil {
			log.Errorf("failed to load or rebuild the next distributed key generator for resharing, skip processing responses for the next distributed key generator: %v", err)
		} else {
			distKeyGens = append(distKeyGens, nextDistKeyGen)
		}
	}

	// Process the responses
	var (
		justifications []*pb.Justification
		resps          []dkg.Response
	)
	for _, response := range req.GetResponses() {
		resp := types.ConvertToVSSResp(response)
		for _, distKeyGen := range distKeyGens {
			j, err := distKeyGen.ProcessResponse(resp)
			if err != nil {
				// skip the responses
				log.WithFields(log.Fields{
					"round":           req.GetRound(),
					"code_commitment": codeCommitmentHex,
					"index":           response.GetIndex(),
					"vss_response":    response.GetVssResponse(),
				}).Errorf("failed to process the response: %v", err)

				continue
			}

			if j != nil {
				justification, err := types.ConvertToJustificationProto(j)
				if err != nil {
					log.WithFields(log.Fields{
						"index":         j.Index,
						"justification": j.Justification,
					}).Errorf("failed to convert to justification proto: %v", err)

					return nil, status.Errorf(codes.Internal, "failed to convert to justification proto")
				}

				justifications = append(justifications, justification)
			}
		}

		resps = append(resps, *resp)
	}

	if err := s.DKGStore.AddResponses(codeCommitmentHex, req.GetRound(), resps); err != nil {
		log.Errorf("failed to add responses to the DKG state: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to add responses to the DKG state")
	}

	log.Info("All responses have been processed", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	return &pb.ProcessResponsesResponse{
		Justifications: justifications,
	}, nil
}

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
	registrations, err := s.QueryClient.GetAllVerifiedDKGRegistrations(context.Background(), codeCommitmentHex, req.GetRound())
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
	priv, err := s.DKGStore.LoadSealedSecp256k1Key(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.Errorf("failed to load sealed Secp256k1 private key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to load sealed secp256k1 key")
	}

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

// PartialDecryptTDH2 performs TDH2 partial decryption using the sealed Kyber private share.
// TODO: TEE should verify if the request transaction was indeed submitted to the canonical chain and the unique ID
// and round match to prevent any leakage of data by off-chain collusion.
func (s *DKGServer) PartialDecryptTDH2(_ context.Context, req *pb.PartialDecryptTDH2Request) (*pb.PartialDecryptTDH2Response, error) {
	if len(req.GetCodeCommitment()) == 0 || req.GetRound() == 0 || len(req.GetCiphertext()) == 0 || len(req.GetGlobalPubKey()) == 0 || len(req.GetRequesterPubKey()) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "missing required fields")
	}

	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("invalid code commitment: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid code commitment")
	}

	ownPID, ok := s.PIDCache.Get(req.GetRound())
	if !ok {
		log.Errorf("PID not found in cache for round %d", req.GetRound())

		return nil, status.Errorf(codes.FailedPrecondition, "PID not found: SetupDKGNetwork may not have been called for this round")
	}
	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	// Load DistKeyShare from cache or sealed store.
	var distKeyShare *dkg.DistKeyShare
	if share, ok := s.DistKeyShareCache.Get(req.GetRound()); ok {
		distKeyShare = share
	} else {
		share, err := store.LoadDistKeyShare(s.Cfg.GetDKGStateDir(), codeCommitmentHex, req.GetRound())
		if err != nil {
			log.Errorf("failed to load dist key share: %v", err)

			return nil, status.Errorf(codes.Internal, "failed to load dist key share")
		}
		distKeyShare = share
		s.DistKeyShareCache.Set(req.GetRound(), share)
	}

	priShare := distKeyShare.PriShare()
	if priShare == nil || priShare.V == nil {
		return nil, status.Errorf(codes.Internal, "private share not available")
	}

	privShare, err := bytes2PrivateShare(priShare.V)
	if err != nil {
		log.Errorf("failed to marshal private share: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal private share")
	}

	pubKey, err := buildTDH2PublicKey(req.GetGlobalPubKey())
	if err != nil {
		log.Errorf("failed to create TDH2 public key: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to build TDH2 public key")
	}
	defer pubKey.Free()

	ct := &mpc.TDH2Ciphertext{Bytes: req.GetCiphertext()}

	pd, err := mpc.TDH2PartialDecrypt(int(ownPID), privShare, pubKey, ct, req.GetLabel())
	if err != nil {
		log.Errorf("TDH2 partial decrypt failed: %v", err)

		return nil, status.Errorf(codes.Internal, "partial decrypt failed")
	}

	// Compute pub_share = V * G for this validator.
	pubShareBz, err := marshalPubShare(priShare.V)
	if err != nil {
		log.Errorf("failed to marshal pub share: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to marshal pub share")
	}

	encryptedPartial, ephPubKey, err := encryptPartialToRequester(req.GetRequesterPubKey(), pd.Bytes)
	if err != nil {
		log.Errorf("failed to encrypt partial: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to encrypt partial")
	}

	signature, err := s.signPartialDecryptResponse(req.GetCodeCommitment(), req.GetRound(), encryptedPartial, ephPubKey, pubShareBz)
	if err != nil {
		log.Errorf("failed to sign partial decrypt response: %v", err)

		return nil, status.Errorf(codes.Internal, "failed to sign partial decrypt response")
	}

	return &pb.PartialDecryptTDH2Response{
		EncryptedPartialDecryption: encryptedPartial,
		EphemeralPubKey:            ephPubKey,
		PubShare:                   pubShareBz,
		Signature:                  signature,
	}, nil
}

func (s *DKGServer) signPartialDecryptResponse(codeCommitment []byte, round uint32, encryptedPartial []byte, ephPubKey []byte, pubShareBz []byte) ([]byte, error) {
	encoded := make([]byte, 0, len(codeCommitment)+4+len(encryptedPartial)+len(ephPubKey)+len(pubShareBz))
	encoded = append(encoded, codeCommitment...)
	encoded = append(encoded, uint32ToBytes(round)...)
	encoded = append(encoded, encryptedPartial...)
	encoded = append(encoded, ephPubKey...)
	encoded = append(encoded, pubShareBz...)
	respHash := ecrypto.Keccak256(encoded)

	codeCommitmentHex := hex.EncodeToString(codeCommitment)
	priv, err := s.DKGStore.LoadSealedSecp256k1Key(codeCommitmentHex, round)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed secp256k1 key: %w", err)
	}

	signature, err := ecrypto.Sign(respHash, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}
	if signature[64] < 27 {
		signature[64] += 27
	}

	return signature, nil
}

func bytes2PrivateShare(scalar kyber.Scalar) (*mpc.TDH2PrivateShare, error) {
	shareBz, err := scalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal private share: %w", err)
	}

	return &mpc.TDH2PrivateShare{Bytes: reverseBytes(shareBz)}, nil
}

func buildTDH2PublicKey(dkgPubKey []byte) (*mpc.TDH2PublicKey, error) {
	tdhPointBytes := append([]byte{0x04, 0x3f}, dkgPubKey...)
	pubKey, err := mpc.TDH2PublicKeyFromPoint(tdhPointBytes)
	if err != nil {
		return nil, fmt.Errorf("build TDH2 public key: %w", err)
	}

	return pubKey, nil
}

func marshalPubShare(scalar kyber.Scalar) ([]byte, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubSharePoint := suite.Point().Mul(scalar, nil)

	return pubSharePoint.MarshalBinary()
}

// encryptPartialToRequester performs secp256k1 ECDH with an ephemeral key and encrypts the partial via AES-GCM.
func encryptPartialToRequester(requesterPubKey []byte, partial []byte) ([]byte, []byte, error) {
	if len(requesterPubKey) != 65 || requesterPubKey[0] != 0x04 {
		return nil, nil, errors.New("invalid requester pubkey")
	}

	requesterECDSA, err := ecrypto.UnmarshalPubkey(requesterPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse requester pubkey: %w", err)
	}

	curve := ecrypto.S256()
	ephemeral, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephemeralECIES := ecies.ImportECDSA(ephemeral)
	requesterECIES := ecies.ImportECDSAPublic(requesterECDSA)
	sharedBytes, err := ephemeralECIES.GenerateShared(requesterECIES, 32, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	h := hkdf.New(sha256.New, sharedBytes, nil, []byte("dkg-tdh2-partial"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(h, aesKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, partial, nil)
	encrypted := append(nonce, ciphertext...)

	ephPub := ecrypto.FromECDSAPub(&ephemeral.PublicKey)

	return encrypted, ephPub, nil
}
