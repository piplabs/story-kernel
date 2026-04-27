package service

import (
	"bytes"
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

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
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
func (s *DKGServer) PartialDecryptTDH2(ctx context.Context, req *pb.PartialDecryptTDH2Request) (*pb.PartialDecryptTDH2Response, error) {
	if err := s.validatePartialDecryptTDH2Request(ctx, req); err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": hex.EncodeToString(req.GetCodeCommitment()),
		}).Errorf("invalid request: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if err := enclave.ValidateCodeCommitment(req.GetCodeCommitment()); err != nil {
		log.Errorf("invalid code commitment: %v", err)

		return nil, status.Errorf(codes.InvalidArgument, "invalid code commitment")
	}

	codeCommitmentHex := hex.EncodeToString(req.GetCodeCommitment())

	roundCtx, err := s.GetOrLoadRoundContext(codeCommitmentHex, req.GetRound())
	if err != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
		}).Errorf("failed to get or load roundContext: %v", err)
		return nil, status.Errorf(codes.FailedPrecondition, "failed to get round context for round %d", req.GetRound())
	}
	network := roundCtx.Network

	ownPID, ok := s.PIDCache.Get(req.GetRound())
	if !ok {
		// PIDCache miss — CachePID may have failed during GenerateDeals
		// (e.g., sealed key not yet available during resharing). Fall back
		// to computing the PID on-the-fly from the sealed key and the
		// round's registrations.
		resolvedPID, err := s.resolvePID(codeCommitmentHex, req.GetRound())
		if err != nil {
			log.WithFields(log.Fields{
				"round":           req.GetRound(),
				"code_commitment": codeCommitmentHex,
			}).Errorf("PID not cached and lazy resolution failed: %v", err)

			return nil, status.Errorf(codes.FailedPrecondition,
				"PID not found and lazy resolution failed: %v", err)
		}
		ownPID = resolvedPID
	}

	// Validate PID is within the expected range for the network.
	if ownPID < 1 || ownPID > network.GetTotal() {
		log.WithFields(log.Fields{
			"round": req.GetRound(),
			"pid":   ownPID,
			"total": network.GetTotal(),
		}).Errorf("PID out of bounds")

		return nil, status.Errorf(codes.FailedPrecondition,
			"invalid PID %d: must be in range [1, %d]", ownPID, network.GetTotal())
	}

	// Load DistKeyShare from cache or sealed store.
	var distKeyShare *dkg.DistKeyShare
	if share, ok := s.DistKeyShareCache.Get(req.GetRound()); ok {
		distKeyShare = share
	} else {
		share, err := s.DKGStore.LoadDistKeyShare(codeCommitmentHex, req.GetRound())
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

	log.WithFields(log.Fields{
		"round":          req.GetRound(),
		"pid":            ownPID,
		"global_pub_key": hex.EncodeToString(req.GetGlobalPubKey()),
		"label":          hex.EncodeToString(req.GetLabel()),
		"ciphertext_len": len(req.GetCiphertext()),
		"ciphertext_hex": hex.EncodeToString(req.GetCiphertext()),
		"priv_share_len": len(privShare.Bytes),
	}).Info("TDH2 partial decrypt: inputs")

	// Verify ciphertext before attempting partial decrypt.
	// Reject invalid ciphertexts before using sealed key material.
	verifyErr := mpc.TDH2Verify(pubKey, ct.Bytes, req.GetLabel())
	if verifyErr != nil {
		log.WithFields(log.Fields{
			"round":           req.GetRound(),
			"code_commitment": codeCommitmentHex,
			"verify_error":    verifyErr.Error(),
		}).Error("TDH2 ciphertext verification failed")

		return nil, status.Errorf(codes.InvalidArgument, "ciphertext verification failed")
	}

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

	signature, err := s.signPartialDecryptResponse(codeCommitmentHex, req.GetRound(), req.GetCiphertext(), encryptedPartial, ephPubKey, pubShareBz)
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

// resolvePID computes the validator's 1-based polynomial index (PID) by
// loading the sealed Ed25519 key for the given round and matching its public
// key against the round's registrations. On success the result is cached in
// PIDCache for future calls. This serves as a lazy fallback when CachePID
// failed during GenerateDeals (e.g., during resharing when the sealed key
// was not yet available).
func (s *DKGServer) resolvePID(codeCommitmentHex string, round uint32) (uint32, error) {
	rc, err := s.GetOrLoadRoundContext(codeCommitmentHex, round)
	if err != nil {
		return 0, fmt.Errorf("load round context: %w", err)
	}

	pid, err := s.matchPIDFromRegistrations(codeCommitmentHex, round, rc.Registrations)
	if err != nil {
		return 0, err
	}

	// Cache the resolved PID so subsequent calls hit the fast path.
	s.PIDCache.Set(round, pid)

	log.WithFields(log.Fields{
		"round":           round,
		"code_commitment": codeCommitmentHex,
		"pid":             pid,
	}).Info("lazily resolved and cached PID from sealed key")

	return pid, nil
}

// matchPIDFromRegistrations loads the sealed Ed25519 key, derives its public
// key, and finds the matching registration index. This is the same logic as
// CachePID but factored out so it can be reused by resolvePID.
func (s *DKGServer) matchPIDFromRegistrations(codeCommitmentHex string, round uint32, regs []*pb.DKGRegistration) (uint32, error) {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
	if err != nil {
		return 0, fmt.Errorf("load sealed Ed25519 key: %w", err)
	}

	ownPubKey := s.Suite.Point().Mul(longterm, nil)
	ownPubKeyBytes, err := ownPubKey.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("marshal own public key: %w", err)
	}

	for _, reg := range regs {
		if bytes.Equal(reg.GetDkgPubKey(), ownPubKeyBytes) {
			if reg.GetIndex() == 0 {
				return 0, errors.New("matched registration has zero index")
			}

			return reg.GetIndex(), nil
		}
	}

	return 0, errors.New("own public key not found in registrations")
}

func (s *DKGServer) validatePartialDecryptTDH2Request(ctx context.Context, req *pb.PartialDecryptTDH2Request) error {
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

	requesterPubKeyHex := hex.EncodeToString(req.GetRequesterPubKey())
	labelHex := hex.EncodeToString(req.GetLabel())
	ciphertextHex := hex.EncodeToString(req.GetCiphertext())
	requestExists, err := s.QueryClient.HasDecryptRequest(ctx, req.GetRound(), requesterPubKeyHex, labelHex, ciphertextHex)
	if err != nil {
		return fmt.Errorf("verify decrypt request existence: %w", err)
	}
	if !requestExists {
		return errors.New("decrypt request does not exist")
	}

	return nil
}

// partialDecryptSignatureMaterial holds the fields committed to by the validator
// signature on a partial decryption response. RLP encoding gives each field an
// unambiguous length prefix, preventing boundary-shift collisions that arise
// from raw concatenation of variable-length byte slices.
type partialDecryptSignatureMaterial struct {
	Round            uint32
	Ciphertext       []byte
	EncryptedPartial []byte
	EphemeralPubKey  []byte
	PubShare         []byte
}

func (s *DKGServer) signPartialDecryptResponse(codeCommitmentHex string, round uint32, ciphertext []byte, encryptedPartial []byte, ephPubKey []byte, pubShareBz []byte) ([]byte, error) {
	material := partialDecryptSignatureMaterial{
		Round:            round,
		Ciphertext:       ciphertext,
		EncryptedPartial: encryptedPartial,
		EphemeralPubKey:  ephPubKey,
		PubShare:         pubShareBz,
	}
	encoded, err := rlp.EncodeToBytes(material)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode signature material: %w", err)
	}
	respHash := ecrypto.Keccak256(encoded)

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
	// Convert kyber scalar (little-endian) to cb-mpc scalar (big-endian),
	// matching the reversal done in bytes2PrivateShare for TDH2PartialDecrypt.
	shareBz, err := scalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal scalar: %w", err)
	}
	defer zeroBytes(shareBz)

	// Compute pub share using cb-mpc (x_i * G) so the serialized point is
	// consistent with the DLEQ proof produced by TDH2PartialDecrypt.
	c, err := curve.NewEd25519()
	if err != nil {
		return nil, fmt.Errorf("create Ed25519 curve: %w", err)
	}
	defer c.Free()

	reversed := reverseBytes(shareBz)
	defer zeroBytes(reversed)

	s := &curve.Scalar{Bytes: reversed}
	point, err := c.MultiplyGenerator(s)
	if err != nil {
		return nil, fmt.Errorf("multiply generator: %w", err)
	}
	defer point.Free()

	return point.Bytes(), nil
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
