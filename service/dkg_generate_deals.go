package service

import (
	"bytes"
	"context"
	"encoding/hex"

	"crypto/aes"
	"crypto/cipher"
	"reflect"
	"unsafe"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/protobuf"
	"golang.org/x/crypto/hkdf"
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
		if err := corruptFirstDeal(s, distKeyGen, deals, codeCommitmentHex, req.GetRound()); err != nil {
			log.Warnf("[DEBUG] Failed to corrupt deal: %v", err)
		}
	}

	log.Info("Succeed to generate deals", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	// Set deals into response
	resp := createGenerateDealsResponse(req.GetRound(), req.GetCodeCommitment(), deals)

	return resp, nil
}

// corruptFirstDeal uses reflect to access the dealer's plaintext deal,
// corrupts the share value, re-encrypts with new ECDH, and re-signs.
// Produces a deal that passes all checks except VerifyDeal → complaint.
// DEBUG ONLY — must never be enabled in production.
func corruptFirstDeal(s *DKGServer, distKeyGen *dkg.DistKeyGenerator, deals map[int]*dkg.Deal, ccHex string, round uint32) error {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(ccHex, round)
	if err != nil {
		return errors.Wrap(err, "load longterm key")
	}

	rc, err := s.GetOrLoadRoundContext(ccHex, round)
	if err != nil {
		return errors.Wrap(err, "get round context")
	}

	dealerPub := s.Suite.Point().Mul(longterm, nil)
	hkdfCtx := vssContext(s.Suite, dealerPub, rc.SortedPubKeys)

	// Access dealer via reflect to get plaintext deals
	dkgVal := reflect.ValueOf(distKeyGen).Elem()
	dealerField := dkgVal.FieldByName("dealer")
	if !dealerField.IsValid() {
		return errors.New("cannot access dealer field via reflect")
	}

	// dealer is *vss.Dealer — call PlaintextDeal method
	dealerIface := reflect.NewAt(dealerField.Type(), unsafe.Pointer(dealerField.UnsafeAddr())).Elem().Interface()

	for idx, deal := range deals {
		if idx >= len(rc.SortedPubKeys) {
			continue
		}

		// Get plaintext deal via reflect method call
		dealer := dealerIface.(*vss.Dealer)
		plainDeal, err := dealer.PlaintextDeal(idx)
		if err != nil {
			return errors.Wrapf(err, "get plaintext deal for index %d", idx)
		}

		// Corrupt the share value (XOR with random scalar)
		corruptedShare := s.Suite.Scalar().Add(plainDeal.SecShare.V, s.Suite.Scalar().One())
		corruptedDeal := &vss.Deal{
			SessionID:   plainDeal.SessionID,
			SecShare:    &share.PriShare{I: plainDeal.SecShare.I, V: corruptedShare},
			T:           plainDeal.T,
			Commitments: plainDeal.Commitments,
		}

		// Encode to protobuf
		dealBuff, err := protobuf.Encode(corruptedDeal)
		if err != nil {
			return errors.Wrap(err, "encode corrupted deal")
		}

		// Generate new ephemeral key and encrypt
		newDHSecret := s.Suite.Scalar().Pick(s.Suite.RandomStream())
		newDHPublic := s.Suite.Point().Mul(newDHSecret, nil)
		recipientPub := rc.SortedPubKeys[idx]
		pre := s.Suite.Point().Mul(newDHSecret, recipientPub)

		gcm, err := vssNewAEAD(s.Suite, pre, hkdfCtx)
		if err != nil {
			return errors.Wrap(err, "create AEAD")
		}

		nonce := make([]byte, gcm.NonceSize())
		encrypted := gcm.Seal(nil, nonce, dealBuff, hkdfCtx)

		// Update deal
		newDHBytes, _ := newDHPublic.MarshalBinary()
		newDHSig, err := schnorr.Sign(s.Suite, longterm, newDHBytes)
		if err != nil {
			return errors.Wrap(err, "sign new DH key")
		}

		deal.Deal.DHKey = newDHBytes
		deal.Deal.Signature = newDHSig
		deal.Deal.Nonce = nonce
		deal.Deal.Cipher = encrypted

		// Re-sign at DKG level
		buff, err := deal.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, "marshal corrupted deal")
		}
		deal.Signature, err = schnorr.Sign(s.Suite, longterm, buff)
		if err != nil {
			return errors.Wrap(err, "re-sign corrupted deal")
		}

		log.Warnf("[DEBUG] Corrupted deal share (correct SessionID): recipient=%d round=%d", idx, round)

		return nil
	}

	return nil
}

// vssContext reproduces kyber's vss.context() function
func vssContext(suite dkg.Suite, dealer kyber.Point, verifiers []kyber.Point) []byte {
	h := suite.Hash()
	_, _ = h.Write([]byte("vss-dealer"))
	_, _ = dealer.MarshalTo(h)
	_, _ = h.Write([]byte("vss-verifiers"))
	for _, v := range verifiers {
		_, _ = v.MarshalTo(h)
	}
	return h.Sum(nil)
}

// vssNewAEAD reproduces kyber's vss.newAEAD() function
func vssNewAEAD(suite dkg.Suite, preSharedKey kyber.Point, ctx []byte) (cipher.AEAD, error) {
	preBuff, _ := preSharedKey.MarshalBinary()
	reader := hkdf.New(suite.Hash, preBuff, nil, ctx)
	sharedKey := make([]byte, 32)
	if _, err := reader.Read(sharedKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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
