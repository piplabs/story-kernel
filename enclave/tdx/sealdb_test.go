package tdx

import (
	"bytes"
	"testing"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/enclave/sealdb"
)

// newTestSealedDB constructs a TDX sealed LevelDB backed by the simulator
// in bootstrap mode.
func newTestSealedDB(t *testing.T) (cmtdb.DB, *Backend) {
	t.Helper()
	b, _ := newTestBackend(t)
	dir := t.TempDir()
	db, err := b.NewSealedDB("test", dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, b
}

func TestTDXSealedLevelDB_SetGet(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)

	require.NoError(t, db.Set([]byte("key"), []byte("value")))
	got, err := db.Get([]byte("key"))
	require.NoError(t, err)
	require.Equal(t, []byte("value"), got)
}

func TestTDXSealedLevelDB_Has(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)

	require.NoError(t, db.Set([]byte("present"), []byte("v")))
	ok, err := db.Has([]byte("present"))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = db.Has([]byte("absent"))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestTDXSealedLevelDB_GetMissing(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	got, err := db.Get([]byte("missing"))
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestTDXSealedLevelDB_Delete(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.Set([]byte("k"), []byte("v")))
	require.NoError(t, db.Delete([]byte("k")))
	got, err := db.Get([]byte("k"))
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestTDXSealedLevelDB_SetSync(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.SetSync([]byte("k"), []byte("v")))
	got, err := db.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
}

func TestTDXSealedLevelDB_DeleteSync(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.SetSync([]byte("k"), []byte("v")))
	require.NoError(t, db.DeleteSync([]byte("k")))
	ok, err := db.Has([]byte("k"))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestTDXSealedLevelDB_EmptyKeyRejected(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.ErrorIs(t, db.Set(nil, []byte("v")), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, db.Set([]byte{}, []byte("v")), sealdb.ErrKeyEmpty)
	_, err := db.Get(nil)
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)
}

func TestTDXSealedLevelDB_NilValueRejected(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.ErrorIs(t, db.Set([]byte("k"), nil), sealdb.ErrValueNil)
	require.ErrorIs(t, db.SetSync([]byte("k"), nil), sealdb.ErrValueNil)
}

func TestTDXSealedLevelDB_Iterator(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)

	require.NoError(t, db.Set([]byte("a"), []byte("1")))
	require.NoError(t, db.Set([]byte("b"), []byte("2")))
	require.NoError(t, db.Set([]byte("c"), []byte("3")))

	itr, err := db.Iterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	var vals []string
	for ; itr.Valid(); itr.Next() {
		keys = append(keys, string(itr.Key()))
		vals = append(vals, string(itr.Value()))
	}
	require.Equal(t, []string{"a", "b", "c"}, keys)
	require.Equal(t, []string{"1", "2", "3"}, vals)
}

func TestTDXSealedLevelDB_ReverseIterator(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.Set([]byte("a"), []byte("1")))
	require.NoError(t, db.Set([]byte("b"), []byte("2")))

	itr, err := db.ReverseIterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for ; itr.Valid(); itr.Next() {
		keys = append(keys, string(itr.Key()))
	}
	require.Equal(t, []string{"b", "a"}, keys)
}

func TestTDXSealedLevelDB_Batch(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)

	batch := db.NewBatch()
	require.NoError(t, batch.Set([]byte("k1"), []byte("v1")))
	require.NoError(t, batch.Set([]byte("k2"), []byte("v2")))
	require.NoError(t, batch.Write())
	require.NoError(t, batch.Close())

	for k, v := range map[string]string{"k1": "v1", "k2": "v2"} {
		got, err := db.Get([]byte(k))
		require.NoError(t, err)
		require.Equal(t, []byte(v), got)
	}
}

func TestTDXSealedLevelDB_BatchWriteSync(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)

	batch := db.NewBatch()
	require.NoError(t, batch.Set([]byte("k"), []byte("v")))
	require.NoError(t, batch.Set([]byte("k2"), []byte("v2")))
	require.NoError(t, batch.Delete([]byte("k2")))
	require.NoError(t, batch.WriteSync())
	require.NoError(t, batch.Close())

	got, err := db.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
	got2, err := db.Get([]byte("k2"))
	require.NoError(t, err)
	require.Nil(t, got2)
}

func TestTDXSealedLevelDB_BatchEmptyKey(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	batch := db.NewBatch()
	defer batch.Close()
	require.ErrorIs(t, batch.Set(nil, []byte("v")), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, batch.Set([]byte("k"), nil), sealdb.ErrValueNil)
	require.ErrorIs(t, batch.Delete(nil), sealdb.ErrKeyEmpty)
}

func TestTDXSealedLevelDB_StatsAndPrint(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.Print())
	stats := db.Stats()
	require.NotEmpty(t, stats)
}

func TestTDXSealedLevelDB_Compact(t *testing.T) {
	t.Parallel()
	db, _ := newTestSealedDB(t)
	require.NoError(t, db.Set([]byte("a"), []byte("1")))
	require.NoError(t, db.Compact(nil, nil))
	// Invalid range start >= end.
	require.Error(t, db.Compact([]byte("b"), []byte("a")))
}

func TestTDXSealedLevelDB_CrossInstancePersistence(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "p", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}

	dir := t.TempDir()
	b1 := newTestBackendWithProviders(t, tpm, providers, nil)
	db1, err := b1.NewSealedDB("persist", dir)
	require.NoError(t, err)
	require.NoError(t, db1.Set([]byte("k"), []byte("persistent")))
	require.NoError(t, db1.Close())

	// Reopen with the same TPM (simulator state persists for the lifetime
	// of the simulator instance) and a fresh backend.
	b2 := newTestBackendWithProviders(t, tpm, providers, nil)
	db2, err := b2.NewSealedDB("persist", dir)
	require.NoError(t, err)
	defer db2.Close()
	got, err := db2.Get([]byte("k"))
	require.NoError(t, err)
	require.True(t, bytes.Equal([]byte("persistent"), got))
}

// =============================================================================
// Sealed-DB dispatch test
// =============================================================================

// TestTDX_NewSealedLevelDB_FailsClosedOnSet verifies that the package-level
// shim enclave.NewSealedLevelDB delegates to the TDX backend, opens
// successfully (LevelDB open does not touch the TPM), and surfaces the
// fail-closed stub's error on the first Set, where tdxSeal cannot drive the
// stub TPM. Skips on real TDX hardware where Set would succeed.
func TestTDX_NewSealedLevelDB_FailsClosedOnSet(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	db, err := enclave.NewSealedLevelDB("shim", t.TempDir())
	require.NoError(t, err)
	defer db.Close()
	require.Error(t, db.Set([]byte("k"), []byte("v")))
}
