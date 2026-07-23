package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// =============================================================================
// HasDKGState tests
// =============================================================================

// TestHasDKGState_Empty returns false when no state has been saved.
func TestHasDKGState_Empty(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	cc := "nostate"
	round := uint32(1)

	// Create lock dir so flock can be acquired, but write no state file.
	ensureStateDir(t, store, cc, round)

	has, err := store.HasDKGState(cc, round)
	require.NoError(t, err)
	require.False(t, has, "expected HasDKGState=false when no state exists")
}

// TestHasDKGState_ZeroThreshold returns false when threshold is zero.
func TestHasDKGState_ZeroThreshold(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "zerothr"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 0, // zero threshold → HasDKGState=false
	}, cc, round))

	has, err := store.HasDKGState(cc, round)
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasDKGState_NoPubKeys returns false when pubkeys is empty.
func TestHasDKGState_NoPubKeys(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	cc := "nopubkeys"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{}, // empty pubkeys → HasDKGState=false
		Threshold: 2,
	}, cc, round))

	has, err := store.HasDKGState(cc, round)
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasDKGState_Valid returns true when state has valid threshold and pubkeys.
func TestHasDKGState_Valid(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "validstate"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}, cc, round))

	has, err := store.HasDKGState(cc, round)
	require.NoError(t, err)
	require.True(t, has)
}

// =============================================================================
// SetNextDKGState tests
// =============================================================================

// TestSetNextDKGState_Basic verifies that threshold and pubkeys are persisted.
// Note: FromRound is an in-memory-only field in this version — not persisted to disk.
func TestSetNextDKGState_Basic(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "nextstatetest"

	pub1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	pub2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)

	// Ensure the lock dir exists for flock
	ensureStateDir(t, store, cc, 2)

	err := store.SetNextDKGState(cc, 1, 2, 2, []kyber.Point{pub1, pub2})
	require.NoError(t, err)

	st, err := store.LoadDKGState(cc, 2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), st.Threshold)
	require.Len(t, st.PubKeys, 2)
	// FromRound is in-memory only; not tested via disk round-trip here.
}

// =============================================================================
// SetPrevDKGState tests
// =============================================================================

// TestSetPrevDKGState_SetsAllFieldsWhenEmpty verifies threshold and pubkeys are set on first call.
// Note: PublicCoeffs is an in-memory field in this version — it is NOT persisted to disk.
func TestSetPrevDKGState_SetsAllFieldsWhenEmpty(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "prevstate"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)

	err := store.SetPrevDKGState(cc, round, 2, []kyber.Point{pub}, []kyber.Point{coeff})
	require.NoError(t, err)

	// Threshold and PubKeys are persisted to disk.
	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Equal(t, uint32(2), st.Threshold)
	require.Len(t, st.PubKeys, 1)
	// PublicCoeffs is in-memory only in this version; not stored on disk.
}

// TestSetPrevDKGState_DoesNotOverwriteExistingPubKeysAndThreshold verifies that
// a non-empty state's pubkeys and threshold are preserved on the second call.
// Note: PublicCoeffs is in-memory only in this version — not persisted to disk.
func TestSetPrevDKGState_DoesNotOverwriteExistingPubKeysAndThreshold(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "prevstate2"
	round := uint32(2)

	ensureStateDir(t, store, cc, round)

	// First call sets pubkeys and threshold
	pub1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SetPrevDKGState(cc, round, 2, []kyber.Point{pub1}, []kyber.Point{coeff1}))

	// Second call: state is no longer empty, so pubkeys and threshold should NOT be overwritten
	pub2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SetPrevDKGState(cc, round, 5, []kyber.Point{pub2}, []kyber.Point{coeff2}))

	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	// Threshold and PubKeys should remain from the first call
	require.Equal(t, uint32(2), st.Threshold)
	require.Len(t, st.PubKeys, 1)
	require.True(t, st.PubKeys[0].Equal(pub1), "PubKeys must not be overwritten on second call")
	// PublicCoeffs is in-memory only; not tested via disk persistence here.
}

// =============================================================================
// SetPublicCoeffs tests
// =============================================================================

// TestSetPublicCoeffs_Basic verifies SetPublicCoeffs executes without error.
// Note: PublicCoeffs is in-memory only in this version — not persisted to disk.
func TestSetPublicCoeffs_Basic(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "pubcoeffs"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	coeff1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)

	// SetPublicCoeffs should succeed (even though coeffs are not persisted to disk)
	err := store.SetPublicCoeffs(cc, round, []kyber.Point{coeff1, coeff2})
	require.NoError(t, err)

	// Verify that the state file is created and is loadable
	_, err = store.LoadDKGState(cc, round)
	require.NoError(t, err)
}

// TestSetPublicCoeffs_Overwrite verifies that subsequent SetPublicCoeffs calls succeed.
func TestSetPublicCoeffs_Overwrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "pubcoeffs2"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)
	coeff1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SetPublicCoeffs(cc, round, []kyber.Point{coeff1}))

	coeff2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SetPublicCoeffs(cc, round, []kyber.Point{coeff2}))

	// State should still be loadable without error
	_, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
}

// =============================================================================
// AddProcessedDeals tests
// =============================================================================

// TestAddProcessedDeals_Basic verifies deals are appended to state.
func TestAddProcessedDeals_Basic(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "adddeals"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	deals, err := dkgGen.Deals()
	require.NoError(t, err)

	var dealSlice []dkg.Deal
	for _, d := range deals {
		dealSlice = append(dealSlice, *d)
	}

	require.NoError(t, store.AddProcessedDeals(cc, round, dealSlice, nil))

	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.Deals, len(dealSlice))
}

// TestAddProcessedDeals_Appends verifies subsequent calls append to existing deals.
func TestAddProcessedDeals_Appends(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "adddeals2"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	deals, err := dkgGen.Deals()
	require.NoError(t, err)

	var dealSlice []dkg.Deal
	for _, d := range deals {
		dealSlice = append(dealSlice, *d)
	}

	require.NoError(t, store.AddProcessedDeals(cc, round, dealSlice, nil))
	require.NoError(t, store.AddProcessedDeals(cc, round, dealSlice, nil))

	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.Deals, 2*len(dealSlice))
}

// =============================================================================
// AddProcessedResponses tests
// =============================================================================

// TestAddProcessedResponses_Basic verifies responses are appended to state.
func TestAddProcessedResponses_Basic(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "addresps"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)
	dkgGen2, err := dkg.NewDistKeyGenerator(suite, priv2, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	deals, err := dkgGen.Deals()
	require.NoError(t, err)

	var resp *dkg.Response
	for i, d := range deals {
		if i == 1 {
			r, e := dkgGen2.ProcessDeal(d)
			require.NoError(t, e)
			resp = r
		}
	}
	require.NotNil(t, resp)

	require.NoError(t, store.AddProcessedResponses(cc, round, []dkg.Response{*resp}, nil))

	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.Responses, 1)
}

// TestAddProcessedResponses_Appends verifies that subsequent calls append to existing responses.
func TestAddProcessedResponses_Appends(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "addresps2"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)
	dkgGen2, err := dkg.NewDistKeyGenerator(suite, priv2, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	deals, err := dkgGen.Deals()
	require.NoError(t, err)

	var resp *dkg.Response
	for i, d := range deals {
		if i == 1 {
			r, e := dkgGen2.ProcessDeal(d)
			require.NoError(t, e)
			resp = r
		}
	}
	require.NotNil(t, resp)

	require.NoError(t, store.AddProcessedResponses(cc, round, []dkg.Response{*resp}, nil))
	require.NoError(t, store.AddProcessedResponses(cc, round, []dkg.Response{*resp}, nil))

	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Len(t, st.Responses, 2)
}

// =============================================================================
// justificationsToDisk error path tests
// =============================================================================

// TestJustificationsToDisk_NilInnerFields verifies error on nil inner Justification field.
func TestJustificationsToDisk_NilInnerFields(t *testing.T) {
	t.Parallel()

	badJust := dkg.Justification{
		Index:         0,
		Justification: nil, // nil inner struct
	}

	_, err := justificationsToDisk([]dkg.Justification{badJust})
	require.ErrorContains(t, err, "nil inner fields")
}

// TestJustificationsToDisk_NilDeal verifies error on nil Deal inside Justification.
func TestJustificationsToDisk_NilDeal(t *testing.T) {
	t.Parallel()

	badJust := dkg.Justification{
		Index: 0,
		Justification: &vss.Justification{
			Deal: nil, // nil deal
		},
	}

	_, err := justificationsToDisk([]dkg.Justification{badJust})
	require.ErrorContains(t, err, "nil inner fields")
}

// =============================================================================
// decodePubKey error path tests
// =============================================================================

// TestDecodePubKey_InvalidBase64 verifies error on invalid base64 input.
func TestDecodePubKey_InvalidBase64(t *testing.T) {
	t.Parallel()

	store := newTestDKGStore(t)
	_, err := store.decodePubKey("not!valid@base64#")
	require.ErrorContains(t, err, "failed to decode base64")
}

// TestDecodePubKey_ValidBase64InvalidPoint verifies behavior on valid base64 but invalid point.
func TestDecodePubKey_ValidBase64InvalidPoint(t *testing.T) {
	t.Parallel()

	store := newTestDKGStore(t)
	// Valid base64 of 32 zero bytes — not a valid Edwards25519 point
	zeroPoint := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	// The call may or may not error depending on kyber's tolerance; ensure no panic
	_, _ = store.decodePubKey(zeroPoint)
}

// =============================================================================
// MarshalDistKeyShare / UnmarshalDistKeyShare edge case tests
// =============================================================================

// TestUnmarshalDistKeyShare_Truncated verifies error on truncated binary input.
func TestUnmarshalDistKeyShare_Truncated(t *testing.T) {
	t.Parallel()

	suite := edwards25519.NewBlakeSHA256Ed25519()
	// 2 bytes is not enough to read even the commit count (uint32 = 4 bytes)
	_, err := UnmarshalDistKeyShare([]byte{0, 0}, suite)
	require.Error(t, err)
}

// TestUnmarshalDistKeyShare_Empty verifies error on completely empty input.
func TestUnmarshalDistKeyShare_Empty(t *testing.T) {
	t.Parallel()

	suite := edwards25519.NewBlakeSHA256Ed25519()
	_, err := UnmarshalDistKeyShare([]byte{}, suite)
	require.Error(t, err)
}

// =============================================================================
// loadState error path: corrupt JSON
// =============================================================================

// TestLoadState_CorruptJSON verifies error when state file contains invalid JSON.
func TestLoadState_CorruptJSON(t *testing.T) {
	t.Parallel()

	store := newTestDKGStore(t)
	cc := "corrupt"
	round := uint32(1)

	// Write corrupt JSON directly to the state path
	path := store.statePath(cc, round)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("{invalid json}"), 0o600))

	// LoadDKGState acquires a read lock; ensure lock dir exists
	ensureStateDir(t, store, cc, round)

	_, err := store.LoadDKGState(cc, round)
	require.Error(t, err, "expected error when state JSON is invalid")
}
