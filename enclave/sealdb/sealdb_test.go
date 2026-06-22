package sealdb_test

import (
	"bytes"
	"errors"
	"testing"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb/storage"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/enclave/sealdb"
)

// xorSealer is a deterministic round-trip oracle Sealer used to verify the
// sealdb wrapper logic in isolation from any real TEE backend. It is NOT a
// secure construction — it only confirms that sealdb routes every value
// through Seal/Unseal correctly.
type xorSealer struct{}

var xorKey = bytes.Repeat([]byte{0xA5}, 32)

func (xorSealer) Seal(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i := range p {
		out[i] = p[i] ^ xorKey[i%len(xorKey)]
	}
	return out, nil
}

func (xorSealer) Unseal(s []byte) ([]byte, error) {
	// XOR is its own inverse; reuse the Seal path.
	return xorSealer{}.Seal(s)
}

var _ enclave.Sealer = xorSealer{}

// failingSealer returns controlled errors from Seal/Unseal for negative-path
// coverage.
type failingSealer struct {
	sealErr   error
	unsealErr error
}

func (f failingSealer) Seal([]byte) ([]byte, error)   { return nil, f.sealErr }
func (f failingSealer) Unseal([]byte) ([]byte, error) { return nil, f.unsealErr }

// passthroughSealUnsealFail makes Seal a no-op (so the value can be written)
// but always fails Unseal — used to exercise the Get-side error path.
type passthroughSealUnsealFail struct{}

func (passthroughSealUnsealFail) Seal(p []byte) ([]byte, error) {
	return append([]byte(nil), p...), nil
}

func (passthroughSealUnsealFail) Unseal([]byte) ([]byte, error) {
	return nil, errors.New("synthetic unseal failure")
}

func memOpener(_ string) (storage.Storage, error) { return storage.NewMemStorage(), nil }

func newDB(t *testing.T) cmtdb.DB {
	t.Helper()
	d, err := sealdb.New("rt", t.TempDir(), xorSealer{}, memOpener)
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// =============================================================================
// Constructor tests
// =============================================================================

func TestNewRejectsNilSealer(t *testing.T) {
	_, err := sealdb.New("x", t.TempDir(), nil, memOpener)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil sealer")
}

func TestNewRejectsNilOpener(t *testing.T) {
	_, err := sealdb.New("x", t.TempDir(), xorSealer{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil opener")
}

func TestNewOpenerError(t *testing.T) {
	openErr := errors.New("synthetic open failure")
	_, err := sealdb.New("x", t.TempDir(), xorSealer{}, func(string) (storage.Storage, error) {
		return nil, openErr
	})
	require.Error(t, err)
	require.ErrorIs(t, err, openErr)
}

// =============================================================================
// Get / Set round trip
// =============================================================================

func TestSetGetRoundTrip(t *testing.T) {
	d := newDB(t)

	require.NoError(t, d.Set([]byte("k1"), []byte("v1")))
	got, err := d.Get([]byte("k1"))
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), got)
}

func TestSetSyncGetRoundTrip(t *testing.T) {
	d := newDB(t)

	require.NoError(t, d.SetSync([]byte("k"), []byte("v")))
	got, err := d.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
}

func TestGetMissingKey(t *testing.T) {
	d := newDB(t)

	got, err := d.Get([]byte("missing"))
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestHas(t *testing.T) {
	d := newDB(t)

	has, err := d.Has([]byte("k"))
	require.NoError(t, err)
	require.False(t, has)

	require.NoError(t, d.Set([]byte("k"), []byte("v")))
	has, err = d.Has([]byte("k"))
	require.NoError(t, err)
	require.True(t, has)
}

// =============================================================================
// Validation paths
// =============================================================================

func TestEmptyKeyRejected(t *testing.T) {
	d := newDB(t)

	_, err := d.Get([]byte{})
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)

	_, err = d.Has(nil)
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)

	require.ErrorIs(t, d.Set([]byte{}, []byte("v")), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, d.SetSync(nil, []byte("v")), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, d.Delete([]byte{}), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, d.DeleteSync(nil), sealdb.ErrKeyEmpty)

	_, err = d.Iterator([]byte{}, nil)
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)

	_, err = d.Iterator(nil, []byte{})
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)

	_, err = d.ReverseIterator([]byte{}, nil)
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)

	_, err = d.ReverseIterator(nil, []byte{})
	require.ErrorIs(t, err, sealdb.ErrKeyEmpty)
}

func TestNilValueRejected(t *testing.T) {
	d := newDB(t)
	require.ErrorIs(t, d.Set([]byte("k"), nil), sealdb.ErrValueNil)
	require.ErrorIs(t, d.SetSync([]byte("k"), nil), sealdb.ErrValueNil)
}

// =============================================================================
// Sealer error propagation
// =============================================================================

func TestSealerSealErrorPropagates(t *testing.T) {
	sealErr := errors.New("synthetic seal failure")
	d, err := sealdb.New("e", t.TempDir(), failingSealer{sealErr: sealErr}, memOpener)
	require.NoError(t, err)
	defer d.Close()

	require.ErrorContains(t, d.Set([]byte("k"), []byte("v")), "synthetic seal failure")
	require.ErrorContains(t, d.SetSync([]byte("k"), []byte("v")), "synthetic seal failure")
}

func TestSealerUnsealErrorPropagates(t *testing.T) {
	d, err := sealdb.New("u", t.TempDir(), passthroughSealUnsealFail{}, memOpener)
	require.NoError(t, err)
	defer d.Close()

	require.NoError(t, d.Set([]byte("k"), []byte("v")))

	_, err = d.Get([]byte("k"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "synthetic unseal failure")
}

// =============================================================================
// Delete / DeleteSync
// =============================================================================

func TestDelete(t *testing.T) {
	d := newDB(t)

	require.NoError(t, d.Set([]byte("k"), []byte("v")))
	require.NoError(t, d.Delete([]byte("k")))

	got, err := d.Get([]byte("k"))
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestDeleteSyncNonExistent(t *testing.T) {
	d := newDB(t)
	require.NoError(t, d.DeleteSync([]byte("missing")))
}

// =============================================================================
// Iterator
// =============================================================================

func TestIteratorForwardAndReverse(t *testing.T) {
	d := newDB(t)

	keys := []string{"a", "b", "c", "d"}
	for _, k := range keys {
		require.NoError(t, d.Set([]byte(k), []byte("val_"+k)))
	}

	fwd, err := d.Iterator([]byte("a"), []byte("e"))
	require.NoError(t, err)
	defer fwd.Close()

	var fwdKeys []string
	for fwd.Valid() {
		fwdKeys = append(fwdKeys, string(fwd.Key()))
		// Verify Value() unseals correctly.
		require.Equal(t, []byte("val_"+string(fwd.Key())), fwd.Value())
		fwd.Next()
	}
	require.Equal(t, keys, fwdKeys)

	rev, err := d.ReverseIterator([]byte("a"), []byte("e"))
	require.NoError(t, err)
	defer rev.Close()

	var revKeys []string
	for rev.Valid() {
		revKeys = append(revKeys, string(rev.Key()))
		rev.Next()
	}
	require.Equal(t, []string{"d", "c", "b", "a"}, revKeys)
}

func TestIteratorEmptyDB(t *testing.T) {
	d := newDB(t)

	itr, err := d.Iterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()
	require.False(t, itr.Valid())
	require.NoError(t, itr.Error())

	rev, err := d.ReverseIterator(nil, nil)
	require.NoError(t, err)
	defer rev.Close()
	require.False(t, rev.Valid())
}

func TestIteratorDomain(t *testing.T) {
	d := newDB(t)
	itr, err := d.Iterator([]byte("a"), []byte("z"))
	require.NoError(t, err)
	defer itr.Close()

	s, e := itr.Domain()
	require.Equal(t, []byte("a"), s)
	require.Equal(t, []byte("z"), e)
}

func TestIteratorAssertInvalidPanics(t *testing.T) {
	d := newDB(t)

	itr, err := d.Iterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()
	require.False(t, itr.Valid())

	require.Panics(t, func() { itr.Next() })
	require.Panics(t, func() { itr.Key() })
	require.Panics(t, func() { itr.Value() })
}

// =============================================================================
// Iterator positioning boundary tests
//
// These exercise the Seek/Last branches in newSealedIterator and the
// out-of-domain Valid() guard in sealedIterator.
// =============================================================================

// TestReverseIterator_EndBeyondLastKey covers the "Seek beyond end" path: the
// underlying source's Seek returns invalid, and newSealedIterator falls back
// to source.Last(). The iterator must yield keys in descending order from
// the actual last key.
func TestReverseIterator_EndBeyondLastKey(t *testing.T) {
	d := newDB(t)
	for _, k := range []string{"a", "b", "c"} {
		require.NoError(t, d.Set([]byte(k), []byte("v_"+k)))
	}

	// "z" is beyond every key in the DB; Seek must return false and the
	// iterator must fall back to source.Last() and walk backwards from "c".
	itr, err := d.ReverseIterator([]byte("a"), []byte("z"))
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for itr.Valid() {
		keys = append(keys, string(itr.Key()))
		itr.Next()
	}
	require.Equal(t, []string{"c", "b", "a"}, keys,
		"reverse iterator must walk from the actual last key when end is beyond the data range")
}

// TestReverseIterator_EndExactKey covers the half-open semantics of [start,
// end). When end exactly matches an existing key, that key must NOT appear.
// newSealedIterator detects this via IsKeyInDomain and steps source.Prev().
func TestReverseIterator_EndExactKey(t *testing.T) {
	d := newDB(t)
	for _, k := range []string{"a", "b", "c", "d"} {
		require.NoError(t, d.Set([]byte(k), []byte("v_"+k)))
	}

	itr, err := d.ReverseIterator([]byte("a"), []byte("c"))
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for itr.Valid() {
		keys = append(keys, string(itr.Key()))
		itr.Next()
	}
	// end="c" is half-open; "c" is excluded, "a" is included.
	require.Equal(t, []string{"b", "a"}, keys,
		"reverse iterator must exclude the end key per half-open semantics")
}

// TestReverseIterator_EndInDomain covers the "Seek lands on a key inside the
// requested domain" path: the iterator does NOT need to step Prev to enter
// the domain because the seeked key is already the one that the half-open
// range admits as the upper bound exclusion check rejects.
func TestReverseIterator_EndInDomain(t *testing.T) {
	d := newDB(t)
	for _, k := range []string{"a", "b", "d", "e"} {
		require.NoError(t, d.Set([]byte(k), []byte("v_"+k)))
	}

	// end="c" is inside the domain but matches no existing key. Seek("c")
	// returns the first key >= "c" which is "d"; "d" is NOT in [a, c)
	// so newSealedIterator steps Prev to "b".
	itr, err := d.ReverseIterator([]byte("a"), []byte("c"))
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for itr.Valid() {
		keys = append(keys, string(itr.Key()))
		itr.Next()
	}
	require.Equal(t, []string{"b", "a"}, keys,
		"reverse iterator must step Prev when Seek lands on a key outside the domain")
}

// TestReverseIterator_NilEnd covers the explicit nil-end branch which calls
// source.Last() unconditionally and walks backwards through the entire DB.
func TestReverseIterator_NilEnd(t *testing.T) {
	d := newDB(t)
	for _, k := range []string{"a", "b", "c"} {
		require.NoError(t, d.Set([]byte(k), []byte("v_"+k)))
	}

	itr, err := d.ReverseIterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for itr.Valid() {
		keys = append(keys, string(itr.Key()))
		itr.Next()
	}
	require.Equal(t, []string{"c", "b", "a"}, keys)
}

// TestForwardIterator_OutOfDomainStops covers the half-open upper-bound check
// in Valid(): a forward iterator stops as soon as the source key is >= end.
func TestForwardIterator_OutOfDomainStops(t *testing.T) {
	d := newDB(t)
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		require.NoError(t, d.Set([]byte(k), []byte("v_"+k)))
	}

	// [a, c) admits a, b but stops before c.
	itr, err := d.Iterator([]byte("a"), []byte("c"))
	require.NoError(t, err)
	defer itr.Close()

	var keys []string
	for itr.Valid() {
		keys = append(keys, string(itr.Key()))
		itr.Next()
	}
	require.Equal(t, []string{"a", "b"}, keys,
		"forward iterator must stop when the source key reaches the half-open upper bound")
}

// TestIterator_ValueUnsealError_SurfacesViaError verifies that an unseal
// failure during Value() is reported via Error() rather than silently
// returning nil bytes. Without this, a sealed-blob corruption (e.g.,
// unauthenticated tampering at the storage layer) would be indistinguishable
// from a "value was nil" read at the iterator API boundary.
func TestIterator_ValueUnsealError_SurfacesViaError(t *testing.T) {
	d, err := sealdb.New("u", t.TempDir(), passthroughSealUnsealFail{}, memOpener)
	require.NoError(t, err)
	defer d.Close()

	require.NoError(t, d.Set([]byte("k"), []byte("v")))

	itr, err := d.Iterator(nil, nil)
	require.NoError(t, err)
	defer itr.Close()

	require.True(t, itr.Valid())
	v := itr.Value()
	require.Nil(t, v, "Value must return nil when unseal fails")

	require.Error(t, itr.Error(), "Error must surface the unseal failure")
	require.ErrorContains(t, itr.Error(), "unseal iterator value")
	require.ErrorContains(t, itr.Error(), "synthetic unseal failure")
}

// =============================================================================
// Batch
// =============================================================================

func TestBatchSetWriteAndDelete(t *testing.T) {
	d := newDB(t)

	b := d.NewBatch()
	require.NoError(t, b.Set([]byte("k1"), []byte("v1")))
	require.NoError(t, b.Set([]byte("k2"), []byte("v2")))
	require.NoError(t, b.Delete([]byte("k3"))) // non-existent, ok
	require.NoError(t, b.Write())
	require.NoError(t, b.Close())

	got1, err := d.Get([]byte("k1"))
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), got1)

	got2, err := d.Get([]byte("k2"))
	require.NoError(t, err)
	require.Equal(t, []byte("v2"), got2)
}

func TestBatchWriteSync(t *testing.T) {
	d := newDB(t)
	b := d.NewBatch()
	require.NoError(t, b.Set([]byte("k"), []byte("v")))
	require.NoError(t, b.WriteSync())
	require.NoError(t, b.Close())

	got, err := d.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
}

func TestBatchValidation(t *testing.T) {
	d := newDB(t)
	b := d.NewBatch()
	defer b.Close()

	require.ErrorIs(t, b.Set([]byte{}, []byte("v")), sealdb.ErrKeyEmpty)
	require.ErrorIs(t, b.Set([]byte("k"), nil), sealdb.ErrValueNil)
	require.ErrorIs(t, b.Delete(nil), sealdb.ErrKeyEmpty)
}

func TestBatchSealErrorPropagates(t *testing.T) {
	sealErr := errors.New("synthetic batch seal failure")
	d, err := sealdb.New("be", t.TempDir(), failingSealer{sealErr: sealErr}, memOpener)
	require.NoError(t, err)
	defer d.Close()

	b := d.NewBatch()
	defer b.Close()
	require.ErrorContains(t, b.Set([]byte("k"), []byte("v")), "synthetic batch seal failure")
}

func TestBatchCloseResetsState(t *testing.T) {
	d := newDB(t)
	b := d.NewBatch()
	require.NoError(t, b.Set([]byte("k"), []byte("v")))
	require.NoError(t, b.Close())
	// After Close, Write becomes a no-op on the reset batch.
	require.NoError(t, b.Write())
}

// =============================================================================
// Print / Stats / Compact
// =============================================================================

func TestPrintStats(t *testing.T) {
	d := newDB(t)
	require.NoError(t, d.Print())
	stats := d.Stats()
	require.NotNil(t, stats)
	_, ok := stats["leveldb"]
	require.True(t, ok)
}

func TestCompactValidRange(t *testing.T) {
	d := newDB(t)
	require.NoError(t, d.Compact(nil, nil))
	require.NoError(t, d.Compact([]byte("a"), []byte("z")))
}

func TestCompactInvalidRange(t *testing.T) {
	d := newDB(t)
	err := d.Compact([]byte("z"), []byte("a"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid compact range")

	err = d.Compact([]byte("a"), []byte("a"))
	require.Error(t, err)
}
