package service

import (
	"bytes"
	"context"
	"encoding/hex"

	"crypto/aes"
	"crypto/cipher"

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
		if err := corruptFirstDeal(s, deals, codeCommitmentHex, req.GetRound()); err != nil {
			log.Warnf("[DEBUG] Failed to corrupt deal: %v", err)
		}
	}

	log.Info("Succeed to generate deals", "code_commitment", codeCommitmentHex, "round", req.GetRound())

	// Set deals into response
	resp := createGenerateDealsResponse(req.GetRound(), req.GetCodeCommitment(), deals)

	return resp, nil
}

// corruptFirstDeal decrypts a deal's AEAD cipher, corrupts the plaintext share,
// re-encrypts with the same shared secret, and re-signs at the DKG level.
// This produces a deal that passes both outer Schnorr and inner AEAD verification,
// but fails VSS share verification → StatusComplaint → justification flow.
// DEBUG ONLY — must never be enabled in production.
func corruptFirstDeal(s *DKGServer, deals map[int]*dkg.Deal, ccHex string, round uint32) error {
	longterm, err := s.DKGStore.LoadSealedEd25519Key(ccHex, round)
	if err != nil {
		return errors.Wrap(err, "load longterm key")
	}

	// Get the round context for the verifier public keys
	rc, err := s.GetOrLoadRoundContext(ccHex, round)
	if err != nil {
		return errors.Wrap(err, "get round context")
	}

	// Build hkdfContext (same as kyber's vss.context function)
	dealerPub := s.Suite.Point().Mul(longterm, nil)
	hkdfCtx := vssContext(s.Suite, dealerPub, rc.SortedPubKeys)

	for idx, deal := range deals {
		if len(deal.Deal.Cipher) == 0 || len(deal.Deal.DHKey) == 0 {
			continue
		}

		// Parse the ephemeral DH public key from the deal
		dhKey := s.Suite.Point()
		if err := dhKey.UnmarshalBinary(deal.Deal.DHKey); err != nil {
			return errors.Wrap(err, "unmarshal DH key")
		}

		// Compute ECDH shared secret: dealer_longterm * recipient_dhKey
		// Wait — the deal's DHKey is the DEALER's ephemeral key, not the recipient's.
		// The shared secret is: dealer_ephemeral * recipient_pubkey
		// But we don't have the ephemeral private key anymore.
		//
		// Alternative: use dealer_longterm * recipient_pubkey to derive shared secret.
		// This matches how the RECIPIENT decrypts: recipient_longterm * dealer_dhKey.
		// But dealer_dhKey is the ephemeral public key, not the dealer's longterm key.
		//
		// Actually, the kyber encryption uses:
		//   Dealer side: dhSecret (ephemeral) * vPub (verifier/recipient pubkey) → pre
		//   Verifier side: v.longterm * dhKey (dealer's ephemeral pubkey) → pre
		// Both compute the same ECDH point.
		//
		// We DON'T have the ephemeral private key. It was generated inside Deals()
		// and discarded. So we can't re-encrypt using the same shared secret.
		//
		// Solution: generate a NEW ephemeral key, compute new shared secret,
		// encrypt the corrupted plaintext, and update DHKey + Signature.

		// Generate new ephemeral key pair
		newDHSecret := s.Suite.Scalar().Pick(s.Suite.RandomStream())
		newDHPublic := s.Suite.Point().Mul(newDHSecret, nil)

		// Get recipient's public key (idx is the recipient index in sorted pubkeys)
		if idx >= len(rc.SortedPubKeys) {
			continue
		}
		recipientPub := rc.SortedPubKeys[idx]

		// Compute new shared secret: newDHSecret * recipientPub
		pre := s.Suite.Point().Mul(newDHSecret, recipientPub)

		// Create AEAD cipher with new shared secret
		gcm, err := vssNewAEAD(s.Suite, pre, hkdfCtx)
		if err != nil {
			return errors.Wrap(err, "create AEAD")
		}

		// Build a valid vss.Deal protobuf with a random share value.
		// The share won't match commitments → VerifyDeal fails → complaint.
		fakeDeal := &vss.Deal{
			SessionID: []byte("fake-session-for-justification-test"),
			SecShare: &share.PriShare{
				I: idx,
				V: s.Suite.Scalar().Pick(s.Suite.RandomStream()),
			},
			T:           uint32(rc.Network.GetThreshold()),
			Commitments: []kyber.Point{s.Suite.Point().Pick(s.Suite.RandomStream())},
		}
		fakePlaintext, err := protobuf.Encode(fakeDeal)
		if err != nil {
			return errors.Wrap(err, "encode fake deal")
		}

		// Encrypt with new AEAD
		nonce := make([]byte, gcm.NonceSize())
		encrypted := gcm.Seal(nil, nonce, fakePlaintext, hkdfCtx)

		// Update the deal with new DH key, cipher, nonce
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

		log.Warnf("[DEBUG] Corrupted deal with new AEAD encryption: recipient_index=%d round=%d", idx, round)

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
