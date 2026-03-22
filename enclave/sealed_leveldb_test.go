package enclave

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestSealedLevelDB creates a SealedLevelDB backed by a temporary directory.
// The DB is fully functional for operations that do not require SGX seal/unseal
// (e.g., input validation paths, Has, Delete, Iterator, NewBatch, Print, Stats, Close).
func newTestSealedLevelDB(t *testing.T) *SealedLevelDB {
	t.Helper()
	dir := t.TempDir()
	db, err := newSealedLevelDBWithOpts("test", dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// =============================================================================
// Get validation tests
// =============================================================================

// TestSealedLevelDB_Get_EmptyKey verifies that Get with empty key returns errKeyEmpty.
func TestSealedLevelDB_Get_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.Get([]byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Get_NilKey verifies that Get with nil key returns errKeyEmpty.
func TestSealedLevelDB_Get_NilKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.Get(nil)
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Get_NotFound verifies that Get for a missing key returns nil, nil.
func TestSealedLevelDB_Get_NotFound(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	val, err := db.Get([]byte("nonexistent"))
	require.NoError(t, err)
	require.Nil(t, val, "missing key should return nil value")
}

// =============================================================================
// Has validation tests
// =============================================================================

// TestSealedLevelDB_Has_EmptyKey verifies that Has with empty key returns errKeyEmpty.
func TestSealedLevelDB_Has_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.Has([]byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Has_NotFound verifies that Has returns false for a missing key.
func TestSealedLevelDB_Has_NotFound(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	has, err := db.Has([]byte("nonexistent"))
	require.NoError(t, err)
	require.False(t, has)
}

// =============================================================================
// Set validation tests
// =============================================================================

// TestSealedLevelDB_Set_EmptyKey verifies that Set with empty key returns errKeyEmpty.
func TestSealedLevelDB_Set_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Set([]byte{}, []byte("value"))
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Set_NilValue verifies that Set with nil value returns errValueNil.
func TestSealedLevelDB_Set_NilValue(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Set([]byte("key"), nil)
	require.ErrorIs(t, err, errValueNil)
}

// =============================================================================
// SetSync validation tests
// =============================================================================

// TestSealedLevelDB_SetSync_EmptyKey verifies that SetSync with empty key returns errKeyEmpty.
func TestSealedLevelDB_SetSync_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.SetSync([]byte{}, []byte("value"))
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_SetSync_NilValue verifies that SetSync with nil value returns errValueNil.
func TestSealedLevelDB_SetSync_NilValue(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.SetSync([]byte("key"), nil)
	require.ErrorIs(t, err, errValueNil)
}

// =============================================================================
// Delete validation tests
// =============================================================================

// TestSealedLevelDB_Delete_EmptyKey verifies that Delete with empty key returns errKeyEmpty.
func TestSealedLevelDB_Delete_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Delete([]byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Delete_NonExistentKey verifies that deleting a non-existent key
// does not return an error (LevelDB semantics).
func TestSealedLevelDB_Delete_NonExistentKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Delete([]byte("nonexistent"))
	require.NoError(t, err)
}

// =============================================================================
// DeleteSync validation tests
// =============================================================================

// TestSealedLevelDB_DeleteSync_EmptyKey verifies that DeleteSync with empty key returns errKeyEmpty.
func TestSealedLevelDB_DeleteSync_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.DeleteSync([]byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// =============================================================================
// Iterator validation tests
// =============================================================================

// TestSealedLevelDB_Iterator_EmptyStart verifies that Iterator with empty start returns errKeyEmpty.
func TestSealedLevelDB_Iterator_EmptyStart(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.Iterator([]byte{}, nil)
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Iterator_EmptyEnd verifies that Iterator with empty end returns errKeyEmpty.
func TestSealedLevelDB_Iterator_EmptyEnd(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.Iterator(nil, []byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_Iterator_NilStartEnd verifies that nil start and end are accepted.
func TestSealedLevelDB_Iterator_NilStartEnd(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.Iterator(nil, nil)
	require.NoError(t, err)
	require.NotNil(t, itr)
	// Empty DB: iterator should be invalid immediately
	require.False(t, itr.Valid())
	require.NoError(t, itr.Close())
}

// TestSealedLevelDB_Iterator_Domain verifies that Domain returns the start/end bounds.
func TestSealedLevelDB_Iterator_Domain(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	start := []byte("a")
	end := []byte("z")
	itr, err := db.Iterator(start, end)
	require.NoError(t, err)

	gotStart, gotEnd := itr.Domain()
	require.Equal(t, start, gotStart)
	require.Equal(t, end, gotEnd)
	require.NoError(t, itr.Close())
}

// TestSealedLevelDB_Iterator_EmptyDB verifies that iterating over an empty DB is safe.
func TestSealedLevelDB_Iterator_EmptyDB(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.Iterator([]byte("a"), []byte("z"))
	require.NoError(t, err)
	require.False(t, itr.Valid())
	require.NoError(t, itr.Error())
	require.NoError(t, itr.Close())
}

// =============================================================================
// ReverseIterator validation tests
// =============================================================================

// TestSealedLevelDB_ReverseIterator_EmptyStart verifies that ReverseIterator
// with empty start returns errKeyEmpty.
func TestSealedLevelDB_ReverseIterator_EmptyStart(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.ReverseIterator([]byte{}, nil)
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_ReverseIterator_EmptyEnd verifies that ReverseIterator
// with empty end returns errKeyEmpty.
func TestSealedLevelDB_ReverseIterator_EmptyEnd(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	_, err := db.ReverseIterator(nil, []byte{})
	require.ErrorIs(t, err, errKeyEmpty)
}

// TestSealedLevelDB_ReverseIterator_NilStartEnd verifies that nil start/end are accepted.
func TestSealedLevelDB_ReverseIterator_NilStartEnd(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.ReverseIterator(nil, nil)
	require.NoError(t, err)
	require.NotNil(t, itr)
	// Empty DB: iterator should be invalid immediately
	require.False(t, itr.Valid())
	require.NoError(t, itr.Close())
}

// TestSealedLevelDB_ReverseIterator_Domain verifies that Domain returns the start/end bounds.
func TestSealedLevelDB_ReverseIterator_Domain(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	start := []byte("a")
	end := []byte("z")
	itr, err := db.ReverseIterator(start, end)
	require.NoError(t, err)

	gotStart, gotEnd := itr.Domain()
	require.Equal(t, start, gotStart)
	require.Equal(t, end, gotEnd)
	require.NoError(t, itr.Close())
}

// =============================================================================
// NewBatch tests
// =============================================================================

// TestSealedLevelDB_NewBatch verifies that NewBatch returns a non-nil batch.
func TestSealedLevelDB_NewBatch(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	require.NotNil(t, batch)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Set_EmptyKey verifies that batch Set with empty key returns errKeyEmpty.
func TestSealedLevelDBBatch_Set_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.Set([]byte{}, []byte("value"))
	require.ErrorIs(t, err, errKeyEmpty)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Set_NilValue verifies that batch Set with nil value returns errValueNil.
func TestSealedLevelDBBatch_Set_NilValue(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.Set([]byte("key"), nil)
	require.ErrorIs(t, err, errValueNil)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Delete_EmptyKey verifies that batch Delete with empty key returns errKeyEmpty.
func TestSealedLevelDBBatch_Delete_EmptyKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.Delete([]byte{})
	require.ErrorIs(t, err, errKeyEmpty)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Write_Empty verifies that writing an empty batch succeeds.
func TestSealedLevelDBBatch_Write_Empty(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.Write()
	require.NoError(t, err)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_WriteSync_Empty verifies that WriteSyncing an empty batch succeeds.
func TestSealedLevelDBBatch_WriteSync_Empty(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.WriteSync()
	require.NoError(t, err)
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Delete_NonExistent verifies that deleting a non-existent
// key in a batch succeeds without error.
func TestSealedLevelDBBatch_Delete_NonExistent(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	err := batch.Delete([]byte("nonexistent"))
	require.NoError(t, err)
	require.NoError(t, batch.Write())
	require.NoError(t, batch.Close())
}

// TestSealedLevelDBBatch_Close_ResetsBatch verifies that Close resets the batch.
func TestSealedLevelDBBatch_Close_ResetsBatch(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	batch := db.NewBatch()
	// Delete adds to the batch size
	require.NoError(t, batch.Delete([]byte("key")))
	require.NoError(t, batch.Close())

	// After close, batch should be empty (Write should be a no-op)
	require.NoError(t, batch.Write())
}

// =============================================================================
// Print / Stats / Compact tests
// =============================================================================

// TestSealedLevelDB_Print verifies that Print does not return an error.
func TestSealedLevelDB_Print(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Print()
	require.NoError(t, err)
}

// TestSealedLevelDB_Stats verifies that Stats returns a non-nil map.
func TestSealedLevelDB_Stats(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	stats := db.Stats()
	require.NotNil(t, stats)
	_, hasLevelDB := stats["leveldb"]
	require.True(t, hasLevelDB, "stats should contain 'leveldb' key")
}

// TestSealedLevelDB_Compact_EmptyDB verifies that Compact on an empty DB succeeds.
func TestSealedLevelDB_Compact_EmptyDB(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Compact(nil, nil)
	require.NoError(t, err)
}

// TestSealedLevelDB_Compact_InvalidRange verifies that Compact with start >= end returns error.
func TestSealedLevelDB_Compact_InvalidRange(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Compact([]byte("z"), []byte("a"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid compact range: start >= end")
}

// TestSealedLevelDB_Compact_EqualRange verifies that Compact with start == end returns error.
func TestSealedLevelDB_Compact_EqualRange(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Compact([]byte("a"), []byte("a"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid compact range: start >= end")
}

// TestSealedLevelDB_Compact_ValidRange verifies that Compact with a valid range succeeds.
func TestSealedLevelDB_Compact_ValidRange(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.Compact([]byte("a"), []byte("z"))
	require.NoError(t, err)
}

// =============================================================================
// Close tests
// =============================================================================

// TestSealedLevelDB_Close verifies that Close succeeds.
func TestSealedLevelDB_Close(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, err := newSealedLevelDBWithOpts("close_test", dir, nil)
	require.NoError(t, err)

	err = db.Close()
	require.NoError(t, err)
}

// =============================================================================
// NewSealedLevelDB tests
// =============================================================================

// TestNewSealedLevelDB_CreatesDB verifies that NewSealedLevelDB creates a valid DB.
func TestNewSealedLevelDB_CreatesDB(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	db, err := NewSealedLevelDB("newdb_test", dir)
	require.NoError(t, err)
	require.NotNil(t, db)

	err = db.Close()
	require.NoError(t, err)
}

// TestNewSealedLevelDB_DefaultOptions verifies that nil options get default bloom filter.
func TestNewSealedLevelDB_DefaultOptions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	db, err := newSealedLevelDBWithOpts("default_opts", dir, nil)
	require.NoError(t, err)
	require.NotNil(t, db)
	require.Equal(t, "default_opts", db.name)
	require.Equal(t, dir, db.dir)

	err = db.Close()
	require.NoError(t, err)
}

// TestSealedLevelDB_Has_AfterDelete verifies that Has returns false after deleting a key
// that was previously directly stored in the underlying LevelDB.
func TestSealedLevelDB_Has_AfterDelete(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	// Write directly to the underlying LevelDB to bypass sealing
	require.NoError(t, db.db.Put([]byte("testkey"), []byte("testvalue"), nil))

	has, err := db.Has([]byte("testkey"))
	require.NoError(t, err)
	require.True(t, has)

	require.NoError(t, db.Delete([]byte("testkey")))

	has, err = db.Has([]byte("testkey"))
	require.NoError(t, err)
	require.False(t, has)
}

// TestSealedLevelDB_DeleteSync_NonExistent verifies that DeleteSync for a non-existent key succeeds.
func TestSealedLevelDB_DeleteSync_NonExistent(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	err := db.DeleteSync([]byte("nonexistent"))
	require.NoError(t, err)
}

// =============================================================================
// Iterator assertIsValid panic test
// =============================================================================

// TestSealedLevelDBIterator_AssertIsValid_PanicsWhenInvalid verifies that
// assertIsValid panics when the iterator is invalid.
func TestSealedLevelDBIterator_AssertIsValid_PanicsWhenInvalid(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.Iterator(nil, nil)
	require.NoError(t, err)

	// On empty DB, iterator is immediately invalid
	require.False(t, itr.Valid())

	// Calling Next() on an invalid iterator should panic
	require.Panics(t, func() {
		itr.Next()
	}, "Next on invalid iterator should panic")

	// Calling Key() on an invalid iterator should panic
	require.Panics(t, func() {
		itr.Key()
	}, "Key on invalid iterator should panic")

	// Calling Value() on an invalid iterator should panic
	require.Panics(t, func() {
		itr.Value()
	}, "Value on invalid iterator should panic")

	require.NoError(t, itr.Close())
}

// TestSealedLevelDBIterator_Error_NoError verifies that Error returns nil when no error.
func TestSealedLevelDBIterator_Error_NoError(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.Iterator(nil, nil)
	require.NoError(t, err)
	require.NoError(t, itr.Error())
	require.NoError(t, itr.Close())
}

// TestSealedLevelDBIterator_Valid_BecomesFalseOnSecondCall verifies that once
// Valid() returns false, subsequent calls also return false (sticky invalid).
func TestSealedLevelDBIterator_Valid_StickyInvalid(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	itr, err := db.Iterator(nil, nil)
	require.NoError(t, err)

	require.False(t, itr.Valid())
	require.False(t, itr.Valid(), "invalid state should be sticky")
	require.NoError(t, itr.Close())
}

// =============================================================================
// ReverseIterator with data (using underlying LevelDB directly)
// =============================================================================

// TestSealedLevelDBIterator_ForwardAndReverse verifies that forward and reverse
// iterators traverse keys in the correct order.
func TestSealedLevelDBIterator_ForwardAndReverse(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	// Write directly to underlying LevelDB to bypass seal
	keys := []string{"a", "b", "c", "d"}
	for _, k := range keys {
		require.NoError(t, db.db.Put([]byte(k), []byte("val_"+k), nil))
	}

	// Forward iterator
	fwdItr, err := db.Iterator([]byte("a"), []byte("e"))
	require.NoError(t, err)

	var fwdKeys []string
	for fwdItr.Valid() {
		fwdKeys = append(fwdKeys, string(fwdItr.Key()))
		fwdItr.Next()
	}
	require.Equal(t, keys, fwdKeys)
	require.NoError(t, fwdItr.Close())

	// Reverse iterator
	revItr, err := db.ReverseIterator([]byte("a"), []byte("e"))
	require.NoError(t, err)

	var revKeys []string
	for revItr.Valid() {
		revKeys = append(revKeys, string(revItr.Key()))
		revItr.Next()
	}
	require.Equal(t, []string{"d", "c", "b", "a"}, revKeys)
	require.NoError(t, revItr.Close())
}

// TestSealedLevelDBIterator_Reverse_NilEnd verifies reverse iterator
// with nil end starts from the last key.
func TestSealedLevelDBIterator_Reverse_NilEnd(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	// Write directly to bypass seal
	require.NoError(t, db.db.Put([]byte("x"), []byte("val_x"), nil))
	require.NoError(t, db.db.Put([]byte("y"), []byte("val_y"), nil))
	require.NoError(t, db.db.Put([]byte("z"), []byte("val_z"), nil))

	revItr, err := db.ReverseIterator([]byte("x"), nil)
	require.NoError(t, err)

	var revKeys []string
	for revItr.Valid() {
		revKeys = append(revKeys, string(revItr.Key()))
		revItr.Next()
	}
	require.Equal(t, []string{"z", "y", "x"}, revKeys)
	require.NoError(t, revItr.Close())
}

// TestSealedLevelDBIterator_Forward_NilStart verifies forward iterator
// with nil start begins from the first key.
func TestSealedLevelDBIterator_Forward_NilStart(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	require.NoError(t, db.db.Put([]byte("m"), []byte("val_m"), nil))
	require.NoError(t, db.db.Put([]byte("n"), []byte("val_n"), nil))

	fwdItr, err := db.Iterator(nil, []byte("o"))
	require.NoError(t, err)

	var fwdKeys []string
	for fwdItr.Valid() {
		fwdKeys = append(fwdKeys, string(fwdItr.Key()))
		fwdItr.Next()
	}
	require.Equal(t, []string{"m", "n"}, fwdKeys)
	require.NoError(t, fwdItr.Close())
}

// TestSealedLevelDB_ReverseIterator_EndInDomain verifies the reverse iterator
// behavior when Seek(end) lands on a key that is exactly at the end boundary
// (which is exclusive in domain range).
func TestSealedLevelDB_ReverseIterator_EndInDomain(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	// Insert keys: a, b, c, d
	for _, k := range []string{"a", "b", "c", "d"} {
		require.NoError(t, db.db.Put([]byte(k), []byte("v_"+k), nil))
	}

	// Reverse iterate [b, d) — should return c, b (d is excluded)
	revItr, err := db.ReverseIterator([]byte("b"), []byte("d"))
	require.NoError(t, err)

	var revKeys []string
	for revItr.Valid() {
		revKeys = append(revKeys, string(revItr.Key()))
		revItr.Next()
	}
	require.Equal(t, []string{"c", "b"}, revKeys)
	require.NoError(t, revItr.Close())
}

// TestSealedLevelDB_ReverseIterator_EndBeyondLastKey verifies reverse iterator
// behavior when end is beyond all existing keys.
func TestSealedLevelDB_ReverseIterator_EndBeyondLastKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	require.NoError(t, db.db.Put([]byte("a"), []byte("va"), nil))
	require.NoError(t, db.db.Put([]byte("b"), []byte("vb"), nil))

	// End is "z" which is beyond all keys
	revItr, err := db.ReverseIterator([]byte("a"), []byte("z"))
	require.NoError(t, err)

	var revKeys []string
	for revItr.Valid() {
		revKeys = append(revKeys, string(revItr.Key()))
		revItr.Next()
	}
	require.Equal(t, []string{"b", "a"}, revKeys)
	require.NoError(t, revItr.Close())
}

// TestSealedLevelDB_ReverseIterator_EndExactKey verifies reverse iterator
// when end matches an existing key exactly (the end key is exclusive).
func TestSealedLevelDB_ReverseIterator_EndExactKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	for _, k := range []string{"a", "b", "c"} {
		require.NoError(t, db.db.Put([]byte(k), []byte("v"), nil))
	}

	// [a, c) means c is excluded — should get b, a
	revItr, err := db.ReverseIterator([]byte("a"), []byte("c"))
	require.NoError(t, err)

	var revKeys []string
	for revItr.Valid() {
		revKeys = append(revKeys, string(revItr.Key()))
		revItr.Next()
	}
	require.Equal(t, []string{"b", "a"}, revKeys)
	require.NoError(t, revItr.Close())
}

// TestSealedLevelDB_Iterator_SingleKey verifies that a single-key range works.
func TestSealedLevelDB_Iterator_SingleKey(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	require.NoError(t, db.db.Put([]byte("b"), []byte("vb"), nil))
	require.NoError(t, db.db.Put([]byte("c"), []byte("vc"), nil))

	// [b, c) should return only b
	itr, err := db.Iterator([]byte("b"), []byte("c"))
	require.NoError(t, err)

	require.True(t, itr.Valid())
	require.Equal(t, "b", string(itr.Key()))
	itr.Next()
	require.False(t, itr.Valid())
	require.NoError(t, itr.Close())
}

// TestSealedLevelDBIterator_OutOfDomain verifies that keys outside the domain
// are not returned by the iterator.
func TestSealedLevelDBIterator_OutOfDomain(t *testing.T) {
	t.Parallel()
	db := newTestSealedLevelDB(t)

	require.NoError(t, db.db.Put([]byte("a"), []byte("v"), nil))
	require.NoError(t, db.db.Put([]byte("b"), []byte("v"), nil))
	require.NoError(t, db.db.Put([]byte("c"), []byte("v"), nil))

	// Only iterate over [b, c) -> should only get "b"
	itr, err := db.Iterator([]byte("b"), []byte("c"))
	require.NoError(t, err)

	var gotKeys []string
	for itr.Valid() {
		gotKeys = append(gotKeys, string(itr.Key()))
		itr.Next()
	}
	require.Equal(t, []string{"b"}, gotKeys)
	require.NoError(t, itr.Close())
}
