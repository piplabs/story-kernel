// Package sealdb provides a backend-agnostic LevelDB wrapper that seals every
// value at rest using a caller-supplied enclave.Sealer.
//
// The wrapper exposes the cmtdb.DB interface and is shared by the SGX and TDX
// backends. SGX passes a Gramine-aware OpenFileNoFlock storage opener (flock
// returns ENOSYS on passthrough files); TDX passes the default storage.OpenFile
// because TDX-on-Linux supports flock natively.
//
// Concurrency: callers that share a Sealer across goroutines must ensure the
// Sealer is goroutine-safe. The TDX Sealer takes its own per-call lock around
// the underlying TPM device; the SGX Sealer (ego/ecrypto) is goroutine-safe.
// sealdb does NOT serialize Sealer calls itself.
package sealdb

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	cmtdb "github.com/cometbft/cometbft-db"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/piplabs/story-kernel/enclave"
)

// Errors exported for caller introspection via errors.Is.
var (
	// ErrKeyEmpty is returned when a key is empty or nil.
	ErrKeyEmpty = errors.New("sealdb: key cannot be empty")
	// ErrValueNil is returned when a Set/SetSync value is nil.
	ErrValueNil = errors.New("sealdb: value cannot be nil")
)

// bloomFilterBitsPerKey is the bits-per-key parameter passed to goleveldb's
// Bloom filter. 10 bits/key is the value recommended by the goleveldb tuning
// guide for ~1% false-positive rate, which is a good default for read-heavy
// workloads (lookups dominate over inserts in our cmtdb usage).
const bloomFilterBitsPerKey = 10

// StorageOpener returns a goleveldb storage.Storage for the given absolute
// database path. SGX uses an OpenFileNoFlock variant (Gramine ENOSYS-on-flock
// workaround); TDX-on-Linux uses storage.OpenFile (regular flock works).
//
// Returning storage.Storage rather than passing the path string and
// constructing the DB inside sealdb keeps SGX-specific filesystem behavior
// out of the shared package — sealdb never imports a Gramine-aware module.
type StorageOpener func(path string) (storage.Storage, error)

// New returns a cmtdb.DB whose values are sealed at rest by sealer. The
// directory is opened via opener.
//
// Both sealer and opener must be non-nil; this constructor returns an error
// rather than dereferencing a nil to make wiring bugs loud at startup.
func New(name, dir string, sealer enclave.Sealer, opener StorageOpener) (cmtdb.DB, error) {
	return newWithOpts(name, dir, sealer, opener, nil)
}

func newWithOpts(name, dir string, sealer enclave.Sealer, opener StorageOpener, o *opt.Options) (*sealedDB, error) {
	if sealer == nil {
		return nil, errors.New("sealdb: nil sealer")
	}
	if opener == nil {
		return nil, errors.New("sealdb: nil opener")
	}

	dbPath := filepath.Join(dir, name+".db")

	if o == nil {
		o = &opt.Options{Filter: filter.NewBloomFilter(bloomFilterBitsPerKey)}
	}

	stor, err := opener(dbPath)
	if err != nil {
		return nil, fmt.Errorf("sealdb: failed to open storage: %w", err)
	}

	db, err := leveldb.Open(stor, o)
	if err != nil {
		if lerrors.IsCorrupted(err) {
			log.Warnf("sealdb: database %s is corrupted; attempting recovery", name)
			db, err = leveldb.Recover(stor, o)
		}
	}
	if err != nil {
		_ = stor.Close()
		return nil, fmt.Errorf("sealdb: failed to open leveldb: %w", err)
	}

	log.Infof("sealdb: opened sealed LevelDB: %s", dbPath)

	return &sealedDB{
		db:     db,
		stor:   stor,
		name:   name,
		dir:    dir,
		sealer: sealer,
	}, nil
}

// sealedDB implements cmtdb.DB by sealing every value before write and
// unsealing every value after read.
//
// The stor field is held so Close() can release the underlying flock
// eagerly. See the Close() doc for the full rationale.
type sealedDB struct {
	db     *leveldb.DB
	stor   storage.Storage
	name   string
	dir    string
	sealer enclave.Sealer
}

// Get retrieves a value, returning the plaintext after Sealer.Unseal.
func (d *sealedDB) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrKeyEmpty
	}

	sealedValue, err := d.db.Get(key, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}

	pt, err := d.sealer.Unseal(sealedValue)
	if err != nil {
		return nil, fmt.Errorf("sealdb: failed to unseal value: %w", err)
	}
	return pt, nil
}

// Has returns whether the key is present in the underlying LevelDB.
func (d *sealedDB) Has(key []byte) (bool, error) {
	if len(key) == 0 {
		return false, ErrKeyEmpty
	}
	return d.db.Has(key, nil)
}

// Set seals value via Sealer.Seal and writes the ciphertext.
func (d *sealedDB) Set(key, value []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	if value == nil {
		return ErrValueNil
	}

	ct, err := d.sealer.Seal(value)
	if err != nil {
		return fmt.Errorf("sealdb: failed to seal value: %w", err)
	}
	return d.db.Put(key, ct, nil)
}

// SetSync is like Set but forces an fsync.
func (d *sealedDB) SetSync(key, value []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	if value == nil {
		return ErrValueNil
	}

	ct, err := d.sealer.Seal(value)
	if err != nil {
		return fmt.Errorf("sealdb: failed to seal value: %w", err)
	}
	return d.db.Put(key, ct, &opt.WriteOptions{Sync: true})
}

// Delete removes a key.
func (d *sealedDB) Delete(key []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	return d.db.Delete(key, nil)
}

// DeleteSync is like Delete but forces an fsync.
func (d *sealedDB) DeleteSync(key []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	return d.db.Delete(key, &opt.WriteOptions{Sync: true})
}

// Iterator creates a forward iterator over [start, end).
func (d *sealedDB) Iterator(start, end []byte) (cmtdb.Iterator, error) {
	if (start != nil && len(start) == 0) || (end != nil && len(end) == 0) {
		return nil, ErrKeyEmpty
	}
	itr := d.db.NewIterator(&util.Range{Start: start, Limit: end}, nil)
	return newSealedIterator(itr, start, end, false, d.sealer), nil
}

// ReverseIterator creates a reverse iterator over [start, end).
func (d *sealedDB) ReverseIterator(start, end []byte) (cmtdb.Iterator, error) {
	if (start != nil && len(start) == 0) || (end != nil && len(end) == 0) {
		return nil, ErrKeyEmpty
	}
	itr := d.db.NewIterator(&util.Range{Start: start, Limit: end}, nil)
	return newSealedIterator(itr, start, end, true, d.sealer), nil
}

// Close closes the underlying LevelDB and the storage layer.
//
// BEHAVIOR CHANGE FROM origin/main:
// origin/main relied on Go's GC + finalizer to release the storage file
// lock after leveldb.Close(). On rapid open-close-open cycles (e.g.,
// integration tests, devnet resets) the GC had not yet run when the next
// open attempted to acquire the same flock, surfacing as a spurious
// "resource temporarily unavailable" error. This implementation closes the
// storage handle eagerly so the lock is released by the time Close()
// returns.
//
// Why an explicit stor.Close() is required:
// We construct the DB via leveldb.Open(stor, opts), NOT leveldb.OpenFile().
// Open does NOT take ownership of stor — db.closer is left nil. Only
// OpenFile sets db.closer = stor internally. We use the lower-level Open
// path so we can pass a custom storage opener (SGX Gramine-aware noflock
// vs TDX default flock); the consequence is that we must release the
// storage ourselves.
func (d *sealedDB) Close() error {
	dbErr := d.db.Close()
	storErr := d.stor.Close()
	if dbErr != nil {
		return dbErr
	}
	return storErr
}

// NewBatch creates a new atomic write batch.
func (d *sealedDB) NewBatch() cmtdb.Batch {
	return &sealedBatch{
		db:     d.db,
		batch:  new(leveldb.Batch),
		sealer: d.sealer,
	}
}

// Print logs database stats.
func (d *sealedDB) Print() error {
	stats := &leveldb.DBStats{}
	if err := d.db.Stats(stats); err != nil {
		return err
	}
	log.Infof("sealdb: LevelDB stats: %+v", stats)
	return nil
}

// Stats returns database statistics.
func (d *sealedDB) Stats() map[string]string {
	stats := make(map[string]string)
	leveldbStats := &leveldb.DBStats{}
	if err := d.db.Stats(leveldbStats); err == nil {
		stats["leveldb"] = fmt.Sprintf("%+v", leveldbStats)
	}
	return stats
}

// Compact compacts the underlying DB for the given key range.
func (d *sealedDB) Compact(start, end []byte) error {
	if start != nil && end != nil && len(start) > 0 && len(end) > 0 {
		if bytes.Compare(start, end) >= 0 {
			return errors.New("sealdb: invalid compact range: start >= end")
		}
	}
	r := &util.Range{Start: start, Limit: end}
	return d.db.CompactRange(*r)
}

// =============================================================================
// Batch
// =============================================================================

type sealedBatch struct {
	db     *leveldb.DB
	batch  *leveldb.Batch
	size   int
	sealer enclave.Sealer
}

func (b *sealedBatch) Set(key, value []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	if value == nil {
		return ErrValueNil
	}

	ct, err := b.sealer.Seal(value)
	if err != nil {
		return fmt.Errorf("sealdb: failed to seal value: %w", err)
	}
	b.batch.Put(key, ct)
	b.size += len(key) + len(ct)
	return nil
}

func (b *sealedBatch) Delete(key []byte) error {
	if len(key) == 0 {
		return ErrKeyEmpty
	}
	b.batch.Delete(key)
	b.size += len(key)
	return nil
}

func (b *sealedBatch) Write() error {
	return b.db.Write(b.batch, nil)
}

func (b *sealedBatch) WriteSync() error {
	return b.db.Write(b.batch, &opt.WriteOptions{Sync: true})
}

func (b *sealedBatch) Close() error {
	b.batch.Reset()
	b.size = 0
	return nil
}

// =============================================================================
// Iterator
// =============================================================================

type sealedIterator struct {
	source     iterator.Iterator
	start, end []byte
	isReverse  bool
	isInvalid  bool
	sealer     enclave.Sealer
	// valueErr caches the most recent unseal error from Value() so callers
	// can disambiguate "value was nil" from "unseal failed" via Error().
	// Once set it sticks for the life of the iterator: we cannot tell
	// whether a subsequent Value() success is meaningful when an earlier
	// value failed to unseal — fail-closed for the iterator as a whole.
	valueErr error
}

func newSealedIterator(source iterator.Iterator, start, end []byte, isReverse bool, sealer enclave.Sealer) *sealedIterator {
	if isReverse {
		if end == nil {
			source.Last()
		} else {
			if valid := source.Seek(end); valid {
				eoaKey := source.Key()
				if !cmtdb.IsKeyInDomain(eoaKey, start, end) {
					source.Prev()
				}
			} else {
				source.Last()
			}
		}
	} else {
		if start == nil {
			source.First()
		} else {
			source.Seek(start)
		}
	}
	return &sealedIterator{
		source:    source,
		start:     start,
		end:       end,
		isReverse: isReverse,
		sealer:    sealer,
	}
}

func (itr *sealedIterator) Domain() (start, end []byte) {
	return itr.start, itr.end
}

func (itr *sealedIterator) Valid() bool {
	if itr.isInvalid {
		return false
	}
	if !itr.source.Valid() {
		itr.isInvalid = true
		return false
	}
	key := itr.source.Key()
	if !cmtdb.IsKeyInDomain(key, itr.start, itr.end) {
		itr.isInvalid = true
		return false
	}
	return true
}

func (itr *sealedIterator) Next() {
	itr.assertIsValid()
	if itr.isReverse {
		itr.source.Prev()
	} else {
		itr.source.Next()
	}
}

func (itr *sealedIterator) Key() []byte {
	itr.assertIsValid()
	return itr.source.Key()
}

func (itr *sealedIterator) Value() []byte {
	itr.assertIsValid()
	sealedValue := itr.source.Value()

	pt, err := itr.sealer.Unseal(sealedValue)
	if err != nil {
		// Cache the error so Error() can surface it. Returning nil here
		// matches the cmtdb.Iterator contract (Value never returns an
		// error directly), but a sticky valueErr lets the caller
		// disambiguate via Error() — which is the documented escape
		// hatch for iterator faults.
		itr.valueErr = fmt.Errorf("sealdb: unseal iterator value: %w", err)
		log.Errorf("sealdb: failed to unseal iterator value: %v", err)
		return nil
	}
	return pt
}

// Error reports the first error observed by the iterator, including unseal
// failures from Value() that the cmtdb.Iterator interface cannot return
// directly. The underlying source error takes precedence over a cached
// valueErr because a source error usually invalidates subsequent reads.
func (itr *sealedIterator) Error() error {
	if err := itr.source.Error(); err != nil {
		return err
	}
	return itr.valueErr
}

func (itr *sealedIterator) Close() error {
	itr.source.Release()
	return nil
}

func (itr *sealedIterator) assertIsValid() {
	if !itr.Valid() {
		panic("sealdb: iterator is invalid")
	}
}
