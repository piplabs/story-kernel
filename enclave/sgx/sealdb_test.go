package sgx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/enclave/sealdb"
)

// =============================================================================
// SGX-specific sealed DB wiring tests.
//
// Logic shared with the TDX backend (CRUD, iterator, batch, validation) is
// covered by enclave/sealdb's own test suite. The tests in this file focus on
// the SGX-side wiring: that Backend.NewSealedDB returns a usable cmtdb.DB
// backed by the Gramine-aware noflock opener, and that validation errors
// propagate through the shim.
//
// Tests that exercise the actual ego/ecrypto seal path can only run inside a
// real SGX enclave and so are not unit tests; the validation and constructor
// tests below are runnable on any host.
// =============================================================================

func newTestDB(t *testing.T) (db interface {
	Get([]byte) ([]byte, error)
	Has([]byte) (bool, error)
	Set([]byte, []byte) error
	SetSync([]byte, []byte) error
	Delete([]byte) error
	DeleteSync([]byte) error
	Close() error
}) {
	t.Helper()
	d, err := Backend{}.NewSealedDB("sgx_test", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// =============================================================================
// Constructor: Backend.NewSealedDB returns a usable DB.
// =============================================================================

func TestNewSealedDB_OpenClose(t *testing.T) {
	t.Parallel()
	d, err := Backend{}.NewSealedDB("opentest", t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, d)
	require.NoError(t, d.Close())
}

// =============================================================================
// Validation paths: errors come through the shim from sealdb.
// =============================================================================

func TestNewSealedDB_GetEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	_, err := db.Get([]byte{})
	require.True(t, errors.Is(err, sealdb.ErrKeyEmpty), "want sealdb.ErrKeyEmpty, got %v", err)
}

func TestNewSealedDB_GetNilKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	_, err := db.Get(nil)
	require.True(t, errors.Is(err, sealdb.ErrKeyEmpty))
}

func TestNewSealedDB_HasEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	_, err := db.Has([]byte{})
	require.True(t, errors.Is(err, sealdb.ErrKeyEmpty))
}

func TestNewSealedDB_SetEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.Set([]byte{}, []byte("v")), sealdb.ErrKeyEmpty))
}

func TestNewSealedDB_SetNilValue(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.Set([]byte("k"), nil), sealdb.ErrValueNil))
}

func TestNewSealedDB_SetSyncEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.SetSync([]byte{}, []byte("v")), sealdb.ErrKeyEmpty))
}

func TestNewSealedDB_SetSyncNilValue(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.SetSync([]byte("k"), nil), sealdb.ErrValueNil))
}

func TestNewSealedDB_DeleteEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.Delete([]byte{}), sealdb.ErrKeyEmpty))
}

func TestNewSealedDB_DeleteSyncEmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	require.True(t, errors.Is(db.DeleteSync([]byte{}), sealdb.ErrKeyEmpty))
}

// =============================================================================
// openSGXStorage adapter exercises the noflock fallback.
// =============================================================================

func TestOpenSGXStorage(t *testing.T) {
	t.Parallel()
	stor, err := openSGXStorage(t.TempDir() + "/openstor.db")
	require.NoError(t, err)
	require.NotNil(t, stor)
	require.NoError(t, stor.Close())
}

// TestSGX_NewSealedLevelDB_OK verifies that the package-level shim
// enclave.NewSealedLevelDB delegates to the SGX backend and returns a usable
// cmtdb.DB. The DB itself only fails on Seal/Unseal at runtime, not on open,
// so this test runs on any host.
func TestSGX_NewSealedLevelDB_OK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	db, err := enclave.NewSealedLevelDB("shim_db", dir)
	require.NoError(t, err)
	require.NotNil(t, db)
	require.NoError(t, db.Close())
}
