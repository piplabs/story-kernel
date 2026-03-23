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

// plaintextSealer is a test-only sealer that writes/reads data as plaintext
// (no SGX sealing). This allows testing the encode/decode logic without an
// SGX enclave.
type plaintextSealer struct{}

func (plaintextSealer) SealToFile(data []byte, path string) error {
	return os.WriteFile(path, data, 0o600)
}

func (plaintextSealer) UnsealFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// newTestDKGStore creates a DKGStore backed by a temporary directory with
// a plaintext sealer (no SGX required).
func newTestDKGStore(t *testing.T) *DKGStore {
	t.Helper()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	stateDir := filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(keyDir, 0o755))
	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	return NewDKGStoreWithSealer(keyDir, stateDir, suite, plaintextSealer{})
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

// TestSetPrivateCoeffs_RoundTrip verifies that polynomial coefficients survive
// the full seal → persist → load → unseal cycle.
func TestSetPrivateCoeffs_RoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	cc := "coefftest1234"
	round := uint32(3)

	coeffs := [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
	}

	require.NoError(t, store.SetPrivateCoeffs(cc, round, coeffs))

	loaded, err := store.LoadPrivateCoeffs(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	require.Equal(t, coeffs[0], loaded[0])
	require.Equal(t, coeffs[1], loaded[1])
}

// TestLoadPrivateCoeffs_FileNotExists returns nil when no coefficients have
// been persisted yet (e.g., GenerateDeals not called).
func TestLoadPrivateCoeffs_FileNotExists(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	loaded, err := store.LoadPrivateCoeffs("nonexistent", 99)
	require.NoError(t, err)
	require.Nil(t, loaded)
}

// TestSetPrivateCoeffs_Overwrite verifies that writing coefficients twice
// overwrites the previous value correctly.
func TestSetPrivateCoeffs_Overwrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	cc := "overwritetest"
	round := uint32(1)

	first := [][]byte{{0xaa, 0xbb}}
	require.NoError(t, store.SetPrivateCoeffs(cc, round, first))

	second := [][]byte{{0xcc, 0xdd}, {0xee, 0xff}}
	require.NoError(t, store.SetPrivateCoeffs(cc, round, second))

	loaded, err := store.LoadPrivateCoeffs(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	require.Equal(t, second[0], loaded[0])
	require.Equal(t, second[1], loaded[1])
}

// TestSetPrivateCoeffs_RealScalars verifies round-trip with actual Edwards25519
// scalar values (same format used in production).
func TestSetPrivateCoeffs_RealScalars(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "realscalar"
	round := uint32(5)

	// Generate real scalars like kyber does internally
	s1 := suite.Scalar().Pick(suite.RandomStream())
	s2 := suite.Scalar().Pick(suite.RandomStream())
	s3 := suite.Scalar().Pick(suite.RandomStream())

	b1, err := s1.MarshalBinary()
	require.NoError(t, err)
	b2, err := s2.MarshalBinary()
	require.NoError(t, err)
	b3, err := s3.MarshalBinary()
	require.NoError(t, err)

	coeffs := [][]byte{b1, b2, b3}
	require.NoError(t, store.SetPrivateCoeffs(cc, round, coeffs))

	loaded, err := store.LoadPrivateCoeffs(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded, 3)

	// Verify scalars can be deserialized back
	for i, bz := range loaded {
		restored := suite.Scalar()
		require.NoError(t, restored.UnmarshalBinary(bz))
		require.Equal(t, coeffs[i], bz, "coefficient %d mismatch", i)
	}
}

// TestSetPrivateCoeffs_SeparateFromState verifies that private coefficients
// are stored in a separate sealed file, NOT in the JSON state file.
func TestSetPrivateCoeffs_SeparateFromState(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "separatetest"
	round := uint32(1)

	// Create DKG state (JSON)
	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	ensureStateDir(t, store, cc, round)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}, cc, round))

	// Set private coefficients (sealed file)
	coeffs := [][]byte{{0x01}, {0x02}}
	require.NoError(t, store.SetPrivateCoeffs(cc, round, coeffs))

	// Verify state.json does NOT contain private_coeffs
	stateBytes, err := os.ReadFile(store.statePath(cc, round))
	require.NoError(t, err)
	require.NotContains(t, string(stateBytes), "private_coeffs",
		"private coefficients must NOT appear in plaintext state.json")

	// Verify sealed file exists separately
	_, err = os.Stat(store.privateCoeffsPath(cc, round))
	require.NoError(t, err, "sealed coefficients file must exist")

	// Verify both can be loaded independently
	st, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Equal(t, uint32(2), st.Threshold)

	loaded, err := store.LoadPrivateCoeffs(cc, round)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
}

// TestSaveStateAtomicWrite verifies that saveState writes atomically via
// a temp file + rename, so no .tmp file remains after a successful write.
func TestSaveStateAtomicWrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "atomictest1234"
	round := uint32(1)

	ensureStateDir(t, store, codeCommitment, round)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}, codeCommitment, round))

	// Verify final state file exists and is readable
	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Equal(t, uint32(2), st.Threshold)

	// Verify no leftover .tmp file
	tmpPath := store.statePath(codeCommitment, round) + ".tmp"
	_, err = os.Stat(tmpPath)
	require.True(t, os.IsNotExist(err), "temp file should not remain after successful atomic write")
}

// TestSaveStateOverwrite verifies that saveState overwrites an existing state
// file atomically without leaving corrupt data.
func TestSaveStateOverwrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	codeCommitment := "overwriteatomic"
	round := uint32(1)

	ensureStateDir(t, store, codeCommitment, round)

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)

	// Write initial state
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}, codeCommitment, round))

	// Overwrite with new threshold
	require.NoError(t, store.SaveDKGState(&DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 5,
	}, codeCommitment, round))

	st, err := store.LoadDKGState(codeCommitment, round)
	require.NoError(t, err)
	require.Equal(t, uint32(5), st.Threshold, "overwritten state should have new threshold")
}
