// Package dkgutil provides utilities for DKG polynomial persistence and
// restoration. It is separated from the service package to avoid the cb-mpc
// CGO dependency, enabling local testing of cryptographic operations.
package dkgutil

import (
	"encoding/binary"
	"reflect"
	"unsafe"

	"github.com/pkg/errors"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// ExtractDealerPolyCoeffs retrieves the dealer's private polynomial
// coefficients from a DistKeyGenerator instance using reflection. This is
// necessary because the dealer field is unexported in the DKG struct, but
// vss.Dealer exposes PrivatePoly() and PriPoly exposes Coefficients() as
// public methods.
//
// The extracted coefficients are used for persistence so the polynomial can
// be restored after a kernel restart, preventing the loss of the original
// random polynomial that was used to generate deals.
//
// Returns nil coefficients (without error) if the DKG has no dealer
// (e.g., new-committee-only nodes in resharing).
//
// WARNING: Uses reflect/unsafe to access kyber internals. See RestoreDealerPoly
// for kyber version compatibility notes.
func ExtractDealerPolyCoeffs(dkgInst *dkg.DistKeyGenerator, suite *edwards25519.SuiteEd25519) ([][]byte, error) {
	if dkgInst == nil {
		return nil, errors.New("dkg instance is nil")
	}

	dealer, err := getDealerViaReflect(dkgInst)
	if err != nil {
		return nil, errors.Wrap(err, "access dealer via reflect")
	}
	if dealer == nil {
		return nil, nil
	}

	poly := dealer.PrivatePoly()
	if poly == nil {
		return nil, errors.New("dealer has nil private polynomial")
	}

	coeffs := poly.Coefficients()
	defer func() {
		// Zero secret scalar coefficients to prevent heap residue
		for _, c := range coeffs {
			c.Zero()
		}
	}()
	if len(coeffs) == 0 {
		return nil, errors.New("dealer polynomial has no coefficients")
	}

	result := make([][]byte, len(coeffs))
	for i, c := range coeffs {
		bz, err := c.MarshalBinary()
		if err != nil {
			return nil, errors.Wrapf(err, "marshal coefficient[%d]", i)
		}
		result[i] = bz
	}

	return result, nil
}

// RestoreDealerPoly replaces the dealer's internal polynomial state in a
// DistKeyGenerator with previously persisted coefficients. This is called
// during rebuildInitDKG to restore the exact polynomial that was used to
// generate deals before a restart.
//
// After NewDistKeyGenerator creates a DKG with a random polynomial, this
// function:
// 1. Reconstructs the original PriPoly from persisted coefficients
// 2. Recomputes public commitments from the polynomial
// 3. Recomputes the VSS session ID (used for response verification)
// 4. Replaces the dealer's internal state to match the original
//
// This ensures that responses from peers (which reference the original
// session ID and commitments) can be correctly processed after restart.
//
// WARNING: This function uses reflect and unsafe.Pointer to access unexported
// fields in kyber's DistKeyGenerator, vss.Dealer, and share.PriPoly.
// It depends on the internal field layout of kyber v4.0.0-pre2. If kyber is
// upgraded, the field names, types, or struct layout may change, causing
// silent data corruption or panics. Any kyber version update MUST include
// verification that this function still produces correct results — run
// TestRestoreDealerPoly_FullDKGProtocol and TestComputeSessionID_MatchesKyberInternal.
func RestoreDealerPoly(suite *edwards25519.SuiteEd25519, dkgInst *dkg.DistKeyGenerator, coeffBytes [][]byte) error {
	if len(coeffBytes) == 0 {
		return errors.New("empty coefficient bytes")
	}

	dealer, err := getDealerViaReflect(dkgInst)
	if err != nil {
		return errors.Wrap(err, "access dealer via reflect")
	}
	if dealer == nil {
		return errors.New("dkg instance has no dealer")
	}

	// Unmarshal scalar coefficients
	coeffs := make([]kyber.Scalar, len(coeffBytes))
	defer func() {
		// Zero secret scalar coefficients to prevent heap residue
		for _, c := range coeffs {
			if c != nil {
				c.Zero()
			}
		}
	}()
	for i, bz := range coeffBytes {
		s := suite.Scalar()
		if err := s.UnmarshalBinary(bz); err != nil {
			return errors.Wrapf(err, "unmarshal coefficient[%d]", i)
		}
		coeffs[i] = s
	}

	// Reconstruct private polynomial using kyber's public API
	poly := share.CoefficientsToPriPoly(suite, coeffs)

	// Compute public commitments: F(x) = poly.Commit(G)
	pubPoly := poly.Commit(suite.Point().Base())
	_, secretCommits := pubPoly.Info()

	// Get dealer's public key and verifiers list via reflect
	pub, verifiers, t, err := getDealerPublicInfo(dealer)
	if err != nil {
		return errors.Wrap(err, "get dealer public info")
	}

	// Recompute session ID: hash(dealer_pub || verifiers || commitments || t)
	newSessionID, err := ComputeSessionID(suite, pub, verifiers, secretCommits, t)
	if err != nil {
		return errors.Wrap(err, "compute session ID")
	}

	// Recompute deals for each verifier
	newDeals := make([]*vss.Deal, len(verifiers))
	for i := range verifiers {
		fi := poly.Eval(i)
		newDeals[i] = &vss.Deal{
			SessionID:   newSessionID,
			SecShare:    fi,
			Commitments: secretCommits,
			T:           uint32(t),
		}
	}

	// Create new aggregator and set its internal fields to match the original
	// dealer's aggregator. NewEmptyAggregator creates an aggregator with sid=nil
	// which bypasses session ID verification in responses. We set the full state
	// via reflect to ensure defense-in-depth session ID checking.
	newAgg := vss.NewEmptyAggregator(suite, verifiers)

	if err := setAggregatorState(newAgg, pub, secretCommits, t, newSessionID); err != nil {
		return errors.Wrap(err, "set aggregator state")
	}

	// Replace dealer internal state via reflect
	if err := setDealerState(dealer, poly, coeffs[0], secretCommits, newSessionID, newDeals, newAgg); err != nil {
		return errors.Wrap(err, "set dealer state")
	}

	return nil
}

// getDealerViaReflect extracts the unexported dealer field from
// DistKeyGenerator. Returns nil dealer (without error) if the field is nil
// (resharing receiver-only case).
func getDealerViaReflect(dkgInst *dkg.DistKeyGenerator) (*vss.Dealer, error) {
	dkgVal := reflect.ValueOf(dkgInst).Elem()
	dealerField := dkgVal.FieldByName("dealer")
	if !dealerField.IsValid() {
		return nil, errors.New("dealer field not found in DistKeyGenerator")
	}
	if dealerField.IsNil() {
		return nil, nil
	}

	// Use unsafe.Pointer to access the unexported field value
	dealer := (*vss.Dealer)(unsafe.Pointer(dealerField.Pointer()))

	return dealer, nil
}

// SelfDealerPubKey returns this node's long-term dealer public key from a built
// DistKeyGenerator. DEBUG aid for the re-addition cascade: it lets the
// "generated deals" log bind dealer_index -> the dealer's pubkey, which equals
// this node's prev-round registration dkg_pubkey — so logs can resolve
// dealer_index to a concrete validator (and thus expose markDealersDealt's
// dealer-index vs registration-index misattribution) without guessing.
// Returns (nil, nil) for a receiver-only handler (no dealer).
func SelfDealerPubKey(dkgInst *dkg.DistKeyGenerator) (kyber.Point, error) {
	dealer, err := getDealerViaReflect(dkgInst)
	if err != nil {
		return nil, err
	}
	if dealer == nil {
		return nil, nil
	}

	pub, _, _, err := getDealerPublicInfo(dealer)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

// getDealerPublicInfo extracts the public key, verifiers list, and threshold
// from a vss.Dealer using reflection on its unexported fields.
func getDealerPublicInfo(dealer *vss.Dealer) (kyber.Point, []kyber.Point, int, error) {
	dealerVal := reflect.ValueOf(dealer).Elem()

	pubField := dealerVal.FieldByName("pub")
	if !pubField.IsValid() {
		return nil, nil, 0, errors.New("pub field not found in Dealer")
	}
	pubIface := reflect.NewAt(pubField.Type(), unsafe.Pointer(pubField.UnsafeAddr())).Elem().Interface()
	pub, ok := pubIface.(kyber.Point)
	if !ok {
		return nil, nil, 0, errors.New("pub field is not kyber.Point")
	}

	verifiersField := dealerVal.FieldByName("verifiers")
	if !verifiersField.IsValid() {
		return nil, nil, 0, errors.New("verifiers field not found in Dealer")
	}
	verifiersIface := reflect.NewAt(verifiersField.Type(), unsafe.Pointer(verifiersField.UnsafeAddr())).Elem().Interface()
	verifiers, ok := verifiersIface.([]kyber.Point)
	if !ok {
		return nil, nil, 0, errors.New("verifiers field is not []kyber.Point")
	}

	tField := dealerVal.FieldByName("t")
	if !tField.IsValid() {
		return nil, nil, 0, errors.New("t field not found in Dealer")
	}
	t := int(tField.Int())

	return pub, verifiers, t, nil
}

// ComputeSessionID replicates kyber's unexported sessionID function.
// sessionID = Hash(dealer_pub || verifiers... || commitments... || uint32(t))
func ComputeSessionID(suite *edwards25519.SuiteEd25519, dealer kyber.Point, verifiers, commitments []kyber.Point, t int) ([]byte, error) {
	h := suite.Hash()

	if _, err := dealer.MarshalTo(h); err != nil {
		return nil, errors.Wrap(err, "marshal dealer public key")
	}

	for _, v := range verifiers {
		if _, err := v.MarshalTo(h); err != nil {
			return nil, errors.Wrap(err, "marshal verifier public key")
		}
	}

	for _, c := range commitments {
		if _, err := c.MarshalTo(h); err != nil {
			return nil, errors.Wrap(err, "marshal commitment")
		}
	}

	if err := binary.Write(h, binary.LittleEndian, uint32(t)); err != nil {
		return nil, errors.Wrap(err, "write threshold")
	}

	return h.Sum(nil), nil
}

// setDealerState replaces the internal state of a vss.Dealer using reflection.
// This overwrites: secretPoly, secret, secretCommits, sessionID, deals, and
// Aggregator.
func setDealerState(
	dealer *vss.Dealer,
	poly *share.PriPoly,
	secret kyber.Scalar,
	secretCommits []kyber.Point,
	sessionID []byte,
	deals []*vss.Deal,
	agg *vss.Aggregator,
) error {
	dealerVal := reflect.ValueOf(dealer).Elem()

	// Replace secretPoly
	secretPolyField := dealerVal.FieldByName("secretPoly")
	if !secretPolyField.IsValid() {
		return errors.New("secretPoly field not found in Dealer")
	}
	secretPolyPtr := (*share.PriPoly)(unsafe.Pointer(secretPolyField.Pointer()))
	*secretPolyPtr = *poly

	// Replace secret scalar
	secretField := dealerVal.FieldByName("secret")
	if !secretField.IsValid() {
		return errors.New("secret field not found in Dealer")
	}
	secretIface := reflect.NewAt(secretField.Type(), unsafe.Pointer(secretField.UnsafeAddr())).Elem()
	secretIface.Set(reflect.ValueOf(secret))

	// Replace secretCommits
	commitsField := dealerVal.FieldByName("secretCommits")
	if !commitsField.IsValid() {
		return errors.New("secretCommits field not found in Dealer")
	}
	commitsIface := reflect.NewAt(commitsField.Type(), unsafe.Pointer(commitsField.UnsafeAddr())).Elem()
	commitsIface.Set(reflect.ValueOf(secretCommits))

	// Replace sessionID
	sidField := dealerVal.FieldByName("sessionID")
	if !sidField.IsValid() {
		return errors.New("sessionID field not found in Dealer")
	}
	sidIface := reflect.NewAt(sidField.Type(), unsafe.Pointer(sidField.UnsafeAddr())).Elem()
	sidIface.Set(reflect.ValueOf(sessionID))

	// Replace deals
	dealsField := dealerVal.FieldByName("deals")
	if !dealsField.IsValid() {
		return errors.New("deals field not found in Dealer")
	}
	dealsIface := reflect.NewAt(dealsField.Type(), unsafe.Pointer(dealsField.UnsafeAddr())).Elem()
	dealsIface.Set(reflect.ValueOf(deals))

	// Replace embedded Aggregator
	aggField := dealerVal.FieldByName("Aggregator")
	if !aggField.IsValid() {
		return errors.New("Aggregator field not found in Dealer")
	}
	aggIface := reflect.NewAt(aggField.Type(), unsafe.Pointer(aggField.UnsafeAddr())).Elem()
	aggIface.Set(reflect.ValueOf(agg))

	return nil
}

// setAggregatorState sets the unexported fields of an Aggregator that
// NewEmptyAggregator leaves uninitialized (dealer, commits, t, sid).
// Without these, the aggregator cannot properly verify response session IDs.
//
// WARNING: Uses reflect/unsafe to access kyber vss.Aggregator internals.
// See RestoreDealerPoly for kyber version compatibility notes.
func setAggregatorState(agg *vss.Aggregator, dealer kyber.Point, commits []kyber.Point, t int, sid []byte) error {
	aggVal := reflect.ValueOf(agg).Elem()

	for _, f := range []struct {
		name string
		val  interface{}
	}{
		{"dealer", dealer},
		{"commits", commits},
		{"t", t},
		{"sid", sid},
	} {
		field := aggVal.FieldByName(f.name)
		if !field.IsValid() {
			return errors.Errorf("field %s not found in Aggregator", f.name)
		}

		fPtr := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
		fPtr.Set(reflect.ValueOf(f.val))
	}

	return nil
}
