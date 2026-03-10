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

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// sec1UncompressedPrefix is the SEC1 standard prefix byte for uncompressed elliptic curve points.
	sec1UncompressedPrefix = 0x04
	// tdh2Edwards25519CurveID is the cb-mpc TDH2 custom curve identifier for Edwards25519.
	tdh2Edwards25519CurveID = 0x3f
)

// PartialDecryptTDH2 performs TDH2 partial decryption using the sealed Kyber private share.
// TODO: TEE should verify if the request transaction was indeed submitted to the canonical chain and the unique ID
// and round match to prevent any leakage of data by off-chain collusion.
func (s *DKGServer) PartialDecryptTDH2(ctx context.Context, req *pb.PartialDecryptTDH2Request) (*pb.PartialDecryptTDH2Response, error) {
	if err := validatePartialDecryptTDH2Request(req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": hex.EncodeToString(req.GetCodeCommitment()),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if err := s.verifyRoundMatchesLatestNetwork(ctx, req.GetRound()); err != nil {
		log.WithFields(log.Fields{
			"round": req.GetRound(),
		}).Errorf("round does not match latest network: %v", err)

		return nil, status.Errorf(codes.FailedPrecondition, "round does not match latest active network")
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
	// Zero out the private share bytes after use to minimize exposure in memory.
	defer zeroBytes(privShare.Bytes)

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

func validatePartialDecryptTDH2Request(req *pb.PartialDecryptTDH2Request) error {
	if req.GetRound() == 0 {
		return errors.New("round should be greater than 0")
	}

	if len(req.GetCodeCommitment()) == 0 {
		return errors.New("code commitment is required but missing")
	}

	if len(req.GetCiphertext()) == 0 {
		return errors.New("ciphertext is required but missing")
	}

	if len(req.GetLabel()) == 0 {
		return errors.New("label is required but missing")
	}

	if len(req.GetGlobalPubKey()) == 0 {
		return errors.New("global public key (dkg_pub_key) is required but missing")
	}

	if len(req.GetRequesterPubKey()) == 0 {
		return errors.New("requester public key is required but missing")
	}

	return nil
}

// verifyRoundMatchesLatestNetwork fetches the latest active DKG network and verifies
// that the given round matches the network's round.
func (s *DKGServer) verifyRoundMatchesLatestNetwork(ctx context.Context, round uint32) error {
	latest, err := s.QueryClient.GetLatestActiveDKGNetwork(ctx)
	if err != nil {
		return fmt.Errorf("get latest active DKG network: %w", err)
	}

	if latest.GetRound() != round {
		return fmt.Errorf("round mismatch: request round %d != latest network round %d", round, latest.GetRound())
	}

	return nil
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
	// Zero out the private key after use to minimize exposure in memory.
	defer zeroPrivateKey(priv)

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
	tdhPointBytes := append([]byte{sec1UncompressedPrefix, tdh2Edwards25519CurveID}, dkgPubKey...)
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
	defer zeroPrivateKey(ephemeral)

	ephemeralECIES := ecies.ImportECDSA(ephemeral)
	requesterECIES := ecies.ImportECDSAPublic(requesterECDSA)
	sharedBytes, err := ephemeralECIES.GenerateShared(requesterECIES, 32, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}
	defer zeroBytes(sharedBytes)

	h := hkdf.New(sha256.New, sharedBytes, nil, []byte("dkg-tdh2-partial"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(h, aesKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer zeroBytes(aesKey)

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
