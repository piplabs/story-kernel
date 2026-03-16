package service

import (
	"reflect"
	"unsafe"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
)

// corruptOneDeal modifies one deal's secret share (V+1) while preserving valid
// Schnorr signatures. The corrupted deal passes signature verification but fails
// VSS share verification, causing the recipient to return StatusComplaint.
//
// Approach:
//  1. Access the unexported vss.Dealer inside dkg.DistKeyGenerator via reflect
//  2. Modify the target plaintext deal's share V (V = V + 1)
//  3. Re-encrypt the deal using the dealer's own EncryptedDeal method
//  4. Re-sign the DKG-level deal with the dealer's longterm key
//  5. Replace the target entry in the deals map
func (s *DKGServer) corruptOneDeal(
	codeCommitmentHex string,
	round uint32,
	distKeyGen *dkg.DistKeyGenerator,
	deals map[int]*dkg.Deal,
) error {
	if len(deals) == 0 {
		return errors.New("no deals to corrupt")
	}

	// Pick the first deal as the corruption target.
	var targetIdx int
	for idx := range deals {
		targetIdx = idx
		break
	}

	// Access the unexported vss.Dealer from dkg.DistKeyGenerator via reflect.
	dkgVal := reflect.ValueOf(distKeyGen).Elem()
	dealerField := dkgVal.FieldByName("dealer")
	if !dealerField.IsValid() || dealerField.IsNil() {
		return errors.New("could not access dealer field via reflect")
	}

	//nolint:gosec // Unsafe pointer access required to reach unexported vss.Dealer methods.
	dealer := (*vss.Dealer)(unsafe.Pointer(dealerField.Pointer()))

	// Get the plaintext deal for the target recipient.
	plainDeal, err := dealer.PlaintextDeal(targetIdx)
	if err != nil {
		return errors.Wrap(err, "failed to get plaintext deal")
	}

	// Corrupt the share: V = V + 1. This breaks the polynomial commitment
	// (share no longer matches commitments) while keeping everything else valid.
	originalV := plainDeal.SecShare.V.Clone()
	plainDeal.SecShare.V.Add(plainDeal.SecShare.V, s.Suite.Scalar().One())

	log.WithFields(log.Fields{
		"target_recipient": targetIdx,
		"round":            round,
		"original_V":       originalV.String(),
		"corrupted_V":      plainDeal.SecShare.V.String(),
	}).Warn("Corrupted deal share V for justification testing")

	// Re-encrypt: EncryptedDeal reads from dealer.deals[i] which we just modified
	// in-place, so calling it again produces a valid encryption of the corrupted plaintext.
	newEncDeal, err := dealer.EncryptedDeal(targetIdx)
	if err != nil {
		return errors.Wrap(err, "failed to re-encrypt corrupted deal")
	}

	// Load the dealer's longterm key for DKG-level re-signing.
	longterm, err := s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
	if err != nil {
		return errors.Wrap(err, "failed to load longterm key for re-signing")
	}

	// Re-sign at the DKG level. The DKG signature covers (Index || Cipher).
	oldDeal := deals[targetIdx]
	resignedDeal := &dkg.Deal{
		Index: oldDeal.Index,
		Deal:  newEncDeal,
	}

	dealBytes, err := resignedDeal.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to marshal deal for re-signing")
	}

	resignedDeal.Signature, err = schnorr.Sign(s.Suite, longterm, dealBytes)
	if err != nil {
		return errors.Wrap(err, "failed to re-sign deal at DKG level")
	}

	// Replace the deal in the output map.
	deals[targetIdx] = resignedDeal

	log.WithFields(log.Fields{
		"target_recipient": targetIdx,
		"round":            round,
		"code_commitment":  codeCommitmentHex,
	}).Warn("Deal corruption complete — recipient should issue StatusComplaint")

	return nil
}
