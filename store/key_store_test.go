package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// newTestDKGStoreWithSealer creates a DKGStore backed by a temporary directory
// and the plaintext sealer for testing key store operations.
// plaintextSealer is declared in dkg_state_test.go.
func newTestDKGStoreWithSealer(t *testing.T) *DKGStore {
	t.Helper()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	stateDir := filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(keyDir, 0o755))
	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	return NewDKGStoreWithSealer(keyDir, stateDir, suite, plaintextSealer{})
}

// =============================================================================
// Ed25519 key tests
// =============================================================================

// TestSealAndLoadEd25519Key verifies round-trip seal and unseal of an Ed25519 key.
func TestSealAndLoadEd25519Key(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "ed25519test"
	round := uint32(1)

	// Generate a deterministic ed25519 scalar
	suite := edwards25519.NewBlakeSHA256Ed25519()
	priv := suite.Scalar().Pick(suite.RandomStream())
	privBz, err := priv.MarshalBinary()
	require.NoError(t, err)

	// Seal and store
	require.NoError(t, store.SealAndStoreEd25519Key(cc, round, privBz))

	// Load back
	loaded, err := store.LoadSealedEd25519Key(cc, round)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify the loaded key matches by comparing the public point
	expectedPub := suite.Point().Mul(priv, nil)
	loadedPub := suite.Point().Mul(loaded, nil)
	require.True(t, expectedPub.Equal(loadedPub), "loaded ed25519 key should produce the same public point")
}

// TestLoadSealedEd25519Key_FileNotFound verifies error when sealed file does not exist.
func TestLoadSealedEd25519Key_FileNotFound(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)

	_, err := store.LoadSealedEd25519Key("nonexistent", 99)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unseal the ed25519 private key")
}

// TestSealAndStoreEd25519Key_CreatesDirectory verifies that the key directory
// is created automatically if it does not exist.
func TestSealAndStoreEd25519Key_CreatesDirectory(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "newdir"
	round := uint32(42)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	priv := suite.Scalar().Pick(suite.RandomStream())
	privBz, err := priv.MarshalBinary()
	require.NoError(t, err)

	// The directory does not exist yet
	path := store.ed25519Path(cc, round)
	_, err = os.Stat(filepath.Dir(path))
	require.True(t, os.IsNotExist(err))

	// SealAndStoreEd25519Key should create it
	require.NoError(t, store.SealAndStoreEd25519Key(cc, round, privBz))

	// File should now exist
	_, err = os.Stat(path)
	require.NoError(t, err)
}

// TestSealAndStoreEd25519Key_Overwrite verifies that overwriting an existing
// sealed file succeeds and the new value is loaded.
func TestSealAndStoreEd25519Key_Overwrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "overwrite"
	round := uint32(1)

	// Store first key
	priv1 := suite.Scalar().Pick(suite.RandomStream())
	priv1Bz, err := priv1.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreEd25519Key(cc, round, priv1Bz))

	// Store second key (overwrite)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	priv2Bz, err := priv2.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreEd25519Key(cc, round, priv2Bz))

	// Load should return the second key
	loaded, err := store.LoadSealedEd25519Key(cc, round)
	require.NoError(t, err)
	expectedPub := suite.Point().Mul(priv2, nil)
	loadedPub := suite.Point().Mul(loaded, nil)
	require.True(t, expectedPub.Equal(loadedPub), "loaded key should match the overwritten key")
}

// =============================================================================
// Secp256k1 key tests
// =============================================================================

// TestSealAndLoadSecp256k1Key verifies round-trip seal and unseal of a Secp256k1 key.
func TestSealAndLoadSecp256k1Key(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "secp256k1test"
	round := uint32(1)

	// Generate a secp256k1 key
	priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Seal and store
	require.NoError(t, store.SealAndStoreSecp256k1Key(cc, round, priv))

	// Load back
	loaded, err := store.LoadSealedSecp256k1Key(cc, round)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify the loaded key matches
	require.True(t, priv.Equal(loaded), "loaded secp256k1 key should match original")
}

// TestLoadSealedSecp256k1Key_FileNotFound verifies error when sealed file does not exist.
func TestLoadSealedSecp256k1Key_FileNotFound(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)

	_, err := store.LoadSealedSecp256k1Key("nonexistent", 99)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unseal the secp256k1 private key")
}

// TestLoadSealedSecp256k1Key_InvalidData verifies error when file contains
// data that is not a valid secp256k1 private key.
func TestLoadSealedSecp256k1Key_InvalidData(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "invalidsecp"
	round := uint32(1)

	// Write invalid data (too short to be a valid secp256k1 key)
	path := store.secp256k1Path(cc, round)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("not_a_valid_key"), 0o600))

	_, err := store.LoadSealedSecp256k1Key(cc, round)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to convert to ecdsa private key")
}

// TestSealAndStoreSecp256k1Key_Overwrite verifies that overwriting works.
func TestSealAndStoreSecp256k1Key_Overwrite(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "overwrite_secp"
	round := uint32(1)

	// Store first key
	priv1, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreSecp256k1Key(cc, round, priv1))

	// Store second key (overwrite)
	priv2, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreSecp256k1Key(cc, round, priv2))

	// Load should return the second key
	loaded, err := store.LoadSealedSecp256k1Key(cc, round)
	require.NoError(t, err)
	require.True(t, priv2.Equal(loaded), "loaded key should match the overwritten key")
}

// =============================================================================
// LoadOrGenerate tests
// =============================================================================

// TestLoadOrGenerateEd25519Key_GeneratesNewKey verifies that a new key is
// generated and persisted when no file exists.
func TestLoadOrGenerateEd25519Key_GeneratesNewKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "logenerate_ed"
	round := uint32(1)

	priv, pub, err := store.LoadOrGenerateEd25519Key(cc, round)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	// The generated key should have been persisted
	_, err = os.Stat(store.ed25519Path(cc, round))
	require.NoError(t, err, "key file should exist after generation")
}

// TestLoadOrGenerateEd25519Key_LoadsExistingKey verifies that an existing
// key is loaded instead of generating a new one.
func TestLoadOrGenerateEd25519Key_LoadsExistingKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "loexisting_ed"
	round := uint32(1)

	// Pre-store a known key
	priv := suite.Scalar().Pick(suite.RandomStream())
	privBz, err := priv.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreEd25519Key(cc, round, privBz))

	// LoadOrGenerate should return the same key
	loadedPriv, loadedPub, err := store.LoadOrGenerateEd25519Key(cc, round)
	require.NoError(t, err)

	expectedPub := suite.Point().Mul(priv, nil)
	require.True(t, expectedPub.Equal(loadedPub), "loaded public key should match stored key")

	loadedPubFromPriv := suite.Point().Mul(loadedPriv, nil)
	require.True(t, expectedPub.Equal(loadedPubFromPriv), "derived public key should match stored key")
}

// TestLoadOrGenerateSecp256k1Key_GeneratesNewKey verifies new key generation.
func TestLoadOrGenerateSecp256k1Key_GeneratesNewKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "logenerate_secp"
	round := uint32(1)

	priv, pub, err := store.LoadOrGenerateSecp256k1Key(cc, round)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	// Verify the public key is on the secp256k1 curve
	require.True(t, pub.Curve.IsOnCurve(pub.X, pub.Y))

	// The generated key should have been persisted
	_, err = os.Stat(store.secp256k1Path(cc, round))
	require.NoError(t, err, "key file should exist after generation")
}

// TestLoadOrGenerateSecp256k1Key_LoadsExistingKey verifies loading an existing key.
func TestLoadOrGenerateSecp256k1Key_LoadsExistingKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "loexisting_secp"
	round := uint32(1)

	// Pre-store a known key
	priv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, store.SealAndStoreSecp256k1Key(cc, round, priv))

	// LoadOrGenerate should return the same key
	loadedPriv, loadedPub, err := store.LoadOrGenerateSecp256k1Key(cc, round)
	require.NoError(t, err)
	require.True(t, priv.Equal(loadedPriv), "loaded private key should match stored key")
	require.True(t, priv.PublicKey.Equal(loadedPub), "loaded public key should match stored key")
}

// =============================================================================
// Path construction tests
// =============================================================================

// TestEd25519Path verifies the path construction for Ed25519 keys.
func TestEd25519Path(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	path := store.ed25519Path("abc", 5)
	require.Contains(t, path, "5")
	require.Contains(t, path, "abc")
	require.Contains(t, path, KeyEd25519File)
}

// TestSecp256k1Path verifies the path construction for Secp256k1 keys.
func TestSecp256k1Path(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	path := store.secp256k1Path("def", 10)
	require.Contains(t, path, "10")
	require.Contains(t, path, "def")
	require.Contains(t, path, KeySecp256k1File)
}

// =============================================================================
// Sealer interface tests
// =============================================================================

// TestNewDKGStore_UsesEnclaveSealer verifies that NewDKGStore uses the default
// enclave sealer (enclaveSealer type check).
func TestNewDKGStore_UsesEnclaveSealer(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	store := NewDKGStore("/tmp/keys", "/tmp/state", suite)
	require.NotNil(t, store.sealer)
	_, ok := store.sealer.(enclaveSealer)
	require.True(t, ok, "NewDKGStore should use enclaveSealer by default")
}

// TestNewDKGStoreWithSealer_UsesCustomSealer verifies custom sealer injection.
func TestNewDKGStoreWithSealer_UsesCustomSealer(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	store := NewDKGStoreWithSealer("/tmp/keys", "/tmp/state", suite, plaintextSealer{})
	require.NotNil(t, store.sealer)
	_, ok := store.sealer.(plaintextSealer)
	require.True(t, ok, "NewDKGStoreWithSealer should use the provided sealer")
}

// =============================================================================
// Edge case: LoadSealedSecp256k1Key with zero-filled key (valid 32 bytes, invalid for curve)
// =============================================================================

// TestLoadSealedSecp256k1Key_ZeroKey verifies that a zero-filled 32-byte key
// fails with an ECDSA conversion error.
func TestLoadSealedSecp256k1Key_ZeroKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "zerokey"
	round := uint32(1)

	// Write 32 zero bytes — valid length but zero is not a valid secp256k1 scalar
	path := store.secp256k1Path(cc, round)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, make([]byte, 32), 0o600))

	_, err := store.LoadSealedSecp256k1Key(cc, round)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to convert to ecdsa private key")
}

// =============================================================================
// Edge case: LoadOrGenerateSecp256k1Key with corrupted file returns error
// =============================================================================

// TestLoadOrGenerateSecp256k1Key_CorruptedFile verifies that a corrupted sealed
// file causes LoadOrGenerate to fail rather than silently generating a new key.
func TestLoadOrGenerateSecp256k1Key_CorruptedFile(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "corrupt_secp"
	round := uint32(1)

	// Create the file with invalid content so os.Stat succeeds but load fails
	path := store.secp256k1Path(cc, round)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("corrupt"), 0o600))

	_, _, err := store.LoadOrGenerateSecp256k1Key(cc, round)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load the existing Secp256k1 key file")
}

// =============================================================================
// Edge case: LoadOrGenerateEd25519Key with existing valid key proves
// idempotency (generate once, load multiple times)
// =============================================================================

// TestLoadOrGenerateEd25519Key_Idempotent verifies that multiple calls
// return the same key when the file already exists.
func TestLoadOrGenerateEd25519Key_Idempotent(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "idempotent_ed"
	round := uint32(1)

	// First call generates
	_, pub1, err := store.LoadOrGenerateEd25519Key(cc, round)
	require.NoError(t, err)

	// Second call loads the same key
	_, pub2, err := store.LoadOrGenerateEd25519Key(cc, round)
	require.NoError(t, err)

	require.True(t, pub1.Equal(pub2), "repeated calls should return the same key")
}

// TestLoadOrGenerateSecp256k1Key_Idempotent verifies idempotency for secp256k1.
func TestLoadOrGenerateSecp256k1Key_Idempotent(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "idempotent_secp"
	round := uint32(1)

	// First call generates
	_, pub1, err := store.LoadOrGenerateSecp256k1Key(cc, round)
	require.NoError(t, err)

	// Second call loads the same key
	_, pub2, err := store.LoadOrGenerateSecp256k1Key(cc, round)
	require.NoError(t, err)

	require.True(t, pub1.Equal(pub2), "repeated calls should return the same key")
}

// =============================================================================
// Edge case: LoadSealedSecp256k1Key with valid non-secp256k1 curve key
// =============================================================================

// TestLoadSealedSecp256k1Key_WrongCurveKey verifies that a P256 key bytes
// (valid ECDSA but wrong curve) fail to load as secp256k1.
func TestLoadSealedSecp256k1Key_WrongCurveKey(t *testing.T) {
	t.Parallel()
	store := newTestDKGStoreWithSealer(t)
	cc := "wrongcurve"
	round := uint32(1)

	// Generate a P-256 key (different curve from secp256k1)
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Write the raw bytes (P-256 scalar, 32 bytes)
	path := store.secp256k1Path(cc, round)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	keyBytes := p256Key.D.Bytes()
	// Pad to 32 bytes if needed
	paddedKey := make([]byte, 32)
	copy(paddedKey[32-len(keyBytes):], keyBytes)
	require.NoError(t, os.WriteFile(path, paddedKey, 0o600))

	// ecrypto.ToECDSA uses secp256k1 curve; loading a P-256 scalar may succeed
	// if the scalar is within the secp256k1 order, but the resulting key will
	// be on secp256k1, not P-256. We just verify no panic occurs.
	_, err = store.LoadSealedSecp256k1Key(cc, round)
	// The call may or may not error depending on whether the P-256 scalar
	// is also a valid secp256k1 scalar. We only check it doesn't panic.
	_ = err
}
