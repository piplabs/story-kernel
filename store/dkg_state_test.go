package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// newTestDKGStore creates a DKGStore backed by a temporary directory.
func newTestDKGStore(t *testing.T) *DKGStore {
	t.Helper()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	stateDir := filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(keyDir, 0o755))
	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	return NewDKGStore(keyDir, stateDir, suite)
}

// ensureStateDir creates the lock/state directory so flock can acquire locks.
func ensureStateDir(t *testing.T, store *DKGStore, codeCommitment string, round uint32) {
	t.Helper()
	dir := filepath.Dir(store.statePath(codeCommitment, round))
	require.NoError(t, os.MkdirAll(dir, 0o755))
}

// makeTestJustification creates a minimal dkg.Justification with the given
// dealer and verifier indices for testing persistence. The cryptographic
// content is not meaningful, only the structure matters for serialization.
func makeTestJustification(suite *edwards25519.SuiteEd25519, dealerIndex, verifierIndex uint32) dkg.Justification {
	scalar := suite.Scalar().Pick(suite.RandomStream())
	point := suite.Point().Mul(scalar, nil)

	return dkg.Justification{
		Index: dealerIndex,
		Justification: &vss.Justification{
			SessionID: []byte("test-session"),
			Index:     verifierIndex,
			Deal: &vss.Deal{
				SessionID: []byte("test-deal-session"),
				SecShare: &share.PriShare{
					I: int(verifierIndex), // 0-based, matching kyber convention
					V: scalar,
				},
				T:           2,
				Commitments: []kyber.Point{point},
			},
			Signature: []byte("test-sig"),
		},
	}
}

// TestAddJustifications verifies that justifications can be persisted
// and retrieved through the DKG state.
func TestAddJustifications(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "abcdef1234567890"
	round := uint32(1)

	// Ensure state directory exists for lock file
	ensureStateDir(t, store, codeCommitment, round)

	// Initialize state with required fields so HasDKGState returns true
	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}, codeCommitment, round))

	// Add first batch of justifications
	j1 := makeTestJustification(suite, 0, 1)
	require.NoError(t, store.AddJustifications(codeCommitment, round, []dkg.Justification{j1}))

	// Add second batch of justifications
	j2 := makeTestJustification(suite, 1, 0)
	require.NoError(t, store.AddJustifications(codeCommitment, round, []dkg.Justification{j2}))

	// Load and verify
	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Len(t, st.Justifications, 2, "expected 2 justifications after two AddJustifications calls")
	require.Equal(t, uint32(0), st.Justifications[0].Index)
	require.Equal(t, uint32(1), st.Justifications[1].Index)
}

// TestJustificationRoundTrip verifies that justifications survive
// serialization and deserialization through toDisk/fromDisk.
func TestJustificationRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	j := makeTestJustification(suite, 2, 3)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:        []kyber.Point{pub},
		Threshold:      2,
		Justifications: []dkg.Justification{j},
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)
	require.Len(t, disk.Justifications, 1)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Len(t, restored.Justifications, 1)
	require.Equal(t, uint32(2), restored.Justifications[0].Index)
	require.Equal(t, uint32(3), restored.Justifications[0].Justification.Index)
}

// TestEmptyJustificationsOmitted verifies that an empty justifications slice
// is omitted from the JSON representation (omitempty).
func TestEmptyJustificationsOmitted(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
		// No justifications
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)
	require.Empty(t, disk.Justifications)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Empty(t, restored.Justifications)
}

// TestFromRoundRoundTrip verifies that the FromRound field survives
// serialization and deserialization through toDisk/fromDisk.
func TestFromRoundRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
		FromRound: 5,
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)
	require.Equal(t, uint32(5), disk.FromRound)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Equal(t, uint32(5), restored.FromRound)
}

// TestFromRoundPersistence verifies that FromRound is persisted to disk
// and can be loaded back correctly.
func TestFromRoundPersistence(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "fromround1234567890"
	round := uint32(3)

	ensureStateDir(t, store, codeCommitment, round)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
		FromRound: 2,
	}, codeCommitment, round))

	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Equal(t, uint32(2), st.FromRound)
}

// TestFromRoundZeroOmitted verifies that FromRound == 0 is handled correctly
// (omitempty means it won't appear in JSON, but should deserialize to 0).
func TestFromRoundZeroOmitted(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
		FromRound: 0,
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Equal(t, uint32(0), restored.FromRound)
}

// TestPublicCoeffsRoundTrip verifies that PublicCoeffs survive
// serialization and deserialization through toDisk/fromDisk.
func TestPublicCoeffsRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff1 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff2 := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:      []kyber.Point{pub},
		Threshold:    2,
		FromRound:    5,
		PublicCoeffs: []kyber.Point{coeff1, coeff2},
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)
	require.Len(t, disk.PublicCoeffsBase64, 2)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Len(t, restored.PublicCoeffs, 2)
	require.True(t, restored.PublicCoeffs[0].Equal(coeff1))
	require.True(t, restored.PublicCoeffs[1].Equal(coeff2))
}

// TestPublicCoeffsPersistence verifies that PublicCoeffs are persisted to disk
// and can be loaded back correctly via SetPrevDKGState.
func TestPublicCoeffsPersistence(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "pubcoeffs1234567890"
	round := uint32(3)

	ensureStateDir(t, store, codeCommitment, round)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	coeff := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SetPrevDKGState(codeCommitment, round, 2, []kyber.Point{pub}, []kyber.Point{coeff}))

	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Len(t, st.PublicCoeffs, 1)
	require.True(t, st.PublicCoeffs[0].Equal(coeff))
}

// TestEmptyPublicCoeffsOmitted verifies that an empty PublicCoeffs slice
// is omitted from the JSON representation.
func TestEmptyPublicCoeffsOmitted(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	original := &DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}

	disk, err := store.toDisk(original)
	require.NoError(t, err)
	require.Empty(t, disk.PublicCoeffsBase64)

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Empty(t, restored.PublicCoeffs)
}

// TestBackwardCompatibility verifies that loading a state file without
// justifications field still works (backward compatibility with existing state files).
func TestBackwardCompatibility(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "backcompat1234567890"
	round := uint32(1)

	ensureStateDir(t, store, codeCommitment, round)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
		// Intentionally no Justifications field
	}, codeCommitment, round))

	// Should load without error even though stored state has no justifications
	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Empty(t, st.Justifications)
}
