package sgx

import (
	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/syndtr/goleveldb/leveldb/storage"

	"github.com/piplabs/story-kernel/enclave/sealdb"
)

// NewSealedDB returns a cmtdb.DB whose values are sealed at rest under the
// running SGX enclave's identity. The Gramine-aware OpenFileNoFlock storage
// opener is required because Gramine returns ENOSYS on flock() for
// passthrough files.
func (b Backend) NewSealedDB(name, dir string) (cmtdb.DB, error) {
	return sealdb.New(name, dir, b, openSGXStorage)
}

// openSGXStorage adapts OpenFileNoFlock to the sealdb.StorageOpener signature.
func openSGXStorage(path string) (storage.Storage, error) {
	return OpenFileNoFlock(path)
}
