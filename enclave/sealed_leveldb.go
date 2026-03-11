package enclave

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/edgelesssys/ego/ecrypto"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	lerrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

var (
	// errKeyEmpty is returned when a key is empty.
	errKeyEmpty = errors.New("key cannot be empty")
	// errValueNil is returned when a value is nil.
	errValueNil = errors.New("value cannot be nil")
)

// SealedLevelDB is a LevelDB wrapper that uses SGX sealing for data protection.
type SealedLevelDB struct {
	db   *leveldb.DB
	name string
	dir  string
}

// NewSealedLevelDB creates a new SGX-sealed LevelDB instance.
func NewSealedLevelDB(name, dir string) (cmtdb.DB, error) {
	return newSealedLevelDBWithOpts(name, dir, nil)
}

func newSealedLevelDBWithOpts(name, dir string, o *opt.Options) (*SealedLevelDB, error) {
	dbPath := filepath.Join(dir, name+".db")

	// Set default options if not provided
	if o == nil {
		o = &opt.Options{
			Filter: filter.NewBloomFilter(10),
		}
	}

	// Use OpenFileNoFlock which gracefully handles Gramine SGX environments
	// where flock is not supported on passthrough files (ENOSYS).
	stor, err := OpenFileNoFlock(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage: %w", err)
	}

	db, err := leveldb.Open(stor, o)
	if err != nil {
		if lerrors.IsCorrupted(err) {
			log.Warnf("Database %s is corrupted. Attempting recovery...", name)
			db, err = leveldb.Recover(stor, o)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open leveldb: %w", err)
	}

	log.Infof("Opened SGX LevelDB: %s", dbPath)

	return &SealedLevelDB{
		db:   db,
		name: name,
		dir:  dir,
	}, nil
}

// Get retrieves a value from the database with SGX unsealing.
func (db *SealedLevelDB) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errKeyEmpty
	}

	sealedValue, err := db.db.Get(key, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil, nil
		}

		return nil, err
	}

	// Unseal the value using SGX with unique key (product key)
	unsealedValue, err := ecrypto.Unseal(sealedValue, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal value: %w", err)
	}

	return unsealedValue, nil
}

// Has checks if a key exists in the database.
func (db *SealedLevelDB) Has(key []byte) (bool, error) {
	if len(key) == 0 {
		return false, errKeyEmpty
	}

	return db.db.Has(key, nil)
}

// Set stores a value in the database with SGX sealing.
func (db *SealedLevelDB) Set(key, value []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}
	if value == nil {
		return errValueNil
	}

	// Seal the value using SGX with unique key (product key)
	sealedValue, err := ecrypto.SealWithUniqueKey(value, nil)
	if err != nil {
		return fmt.Errorf("failed to seal value: %w", err)
	}

	return db.db.Put(key, sealedValue, nil)
}

// SetSync is like Set but forces an fsync.
func (db *SealedLevelDB) SetSync(key, value []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}
	if value == nil {
		return errValueNil
	}

	// Seal the value using SGX with unique key (product key)
	sealedValue, err := ecrypto.SealWithUniqueKey(value, nil)
	if err != nil {
		return fmt.Errorf("failed to seal value: %w", err)
	}

	return db.db.Put(key, sealedValue, &opt.WriteOptions{Sync: true})
}

// Delete removes a key from the database.
func (db *SealedLevelDB) Delete(key []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}

	return db.db.Delete(key, nil)
}

// DeleteSync is like Delete but forces an fsync.
func (db *SealedLevelDB) DeleteSync(key []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}

	return db.db.Delete(key, &opt.WriteOptions{Sync: true})
}

// Iterator creates an iterator over a domain of keys.
func (db *SealedLevelDB) Iterator(start, end []byte) (cmtdb.Iterator, error) {
	if (start != nil && len(start) == 0) || (end != nil && len(end) == 0) {
		return nil, errKeyEmpty
	}

	itr := db.db.NewIterator(&util.Range{Start: start, Limit: end}, nil)

	return newSealedLevelDBIterator(itr, start, end, false), nil
}

// ReverseIterator creates a reverse iterator over a domain of keys.
func (db *SealedLevelDB) ReverseIterator(start, end []byte) (cmtdb.Iterator, error) {
	if (start != nil && len(start) == 0) || (end != nil && len(end) == 0) {
		return nil, errKeyEmpty
	}

	itr := db.db.NewIterator(&util.Range{Start: start, Limit: end}, nil)

	return newSealedLevelDBIterator(itr, start, end, true), nil
}

// Close closes the database.
func (db *SealedLevelDB) Close() error {
	return db.db.Close()
}

// NewBatch creates a new batch for atomic writes.
func (db *SealedLevelDB) NewBatch() cmtdb.Batch {
	return &sealedLevelDBBatch{
		db:    db.db,
		batch: new(leveldb.Batch),
	}
}

// Print prints database stats.
func (db *SealedLevelDB) Print() error {
	stats := &leveldb.DBStats{}
	if err := db.db.Stats(stats); err != nil {
		return err
	}

	log.Infof("LevelDB stats: %+v", stats)

	return nil
}

// Stats returns database statistics.
func (db *SealedLevelDB) Stats() map[string]string {
	stats := make(map[string]string)

	leveldbStats := &leveldb.DBStats{}
	if err := db.db.Stats(leveldbStats); err == nil {
		stats["leveldb"] = fmt.Sprintf("%+v", leveldbStats)
	}

	return stats
}

// Compact compacts the underlying DB for the given key range.
// This is required to implement the cmtdb.DB interface.
func (db *SealedLevelDB) Compact(start, end []byte) error {
	if start != nil && end != nil && len(start) > 0 && len(end) > 0 {
		// Validate range
		if bytes.Compare(start, end) >= 0 {
			return errors.New("invalid compact range: start >= end")
		}
	}

	r := &util.Range{Start: start, Limit: end}

	return db.db.CompactRange(*r)
}

// sealedLevelDBBatch implements cmtdb.Batch with SGX sealing.
type sealedLevelDBBatch struct {
	db    *leveldb.DB
	batch *leveldb.Batch
	size  int
}

func (b *sealedLevelDBBatch) Set(key, value []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}
	if value == nil {
		return errValueNil
	}

	// Seal the value using SGX with unique key (product key)
	sealedValue, err := ecrypto.SealWithUniqueKey(value, nil)
	if err != nil {
		return fmt.Errorf("failed to seal value: %w", err)
	}

	b.batch.Put(key, sealedValue)
	b.size += len(key) + len(sealedValue)

	return nil
}

func (b *sealedLevelDBBatch) Delete(key []byte) error {
	if len(key) == 0 {
		return errKeyEmpty
	}

	b.batch.Delete(key)
	b.size += len(key)

	return nil
}

func (b *sealedLevelDBBatch) Write() error {
	return b.db.Write(b.batch, nil)
}

func (b *sealedLevelDBBatch) WriteSync() error {
	return b.db.Write(b.batch, &opt.WriteOptions{Sync: true})
}

func (b *sealedLevelDBBatch) Close() error {
	b.batch.Reset()
	b.size = 0

	return nil
}

// sealedLevelDBIterator implements cmtdb.Iterator with SGX unsealing.
type sealedLevelDBIterator struct {
	source     iterator.Iterator
	start, end []byte
	isReverse  bool
	isInvalid  bool
}

func newSealedLevelDBIterator(source iterator.Iterator, start, end []byte, isReverse bool) *sealedLevelDBIterator {
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

	return &sealedLevelDBIterator{
		source:    source,
		start:     start,
		end:       end,
		isReverse: isReverse,
		isInvalid: false,
	}
}

func (itr *sealedLevelDBIterator) Domain() (start, end []byte) {
	return itr.start, itr.end
}

func (itr *sealedLevelDBIterator) Valid() bool {
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

func (itr *sealedLevelDBIterator) Next() {
	itr.assertIsValid()
	if itr.isReverse {
		itr.source.Prev()
	} else {
		itr.source.Next()
	}
}

func (itr *sealedLevelDBIterator) Key() []byte {
	itr.assertIsValid()

	return itr.source.Key()
}

func (itr *sealedLevelDBIterator) Value() []byte {
	itr.assertIsValid()
	sealedValue := itr.source.Value()

	// Unseal the value using SGX
	unsealedValue, err := ecrypto.Unseal(sealedValue, nil)
	if err != nil {
		log.Errorf("Failed to unseal iterator value: %v", err)

		return nil
	}

	return unsealedValue
}

func (itr *sealedLevelDBIterator) Error() error {
	return itr.source.Error()
}

func (itr *sealedLevelDBIterator) Close() error {
	itr.source.Release()

	return nil
}

func (itr *sealedLevelDBIterator) assertIsValid() {
	if !itr.Valid() {
		panic("iterator is invalid")
	}
}
