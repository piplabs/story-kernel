package tdx

import (
	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/syndtr/goleveldb/leveldb/storage"

	"github.com/piplabs/story-kernel/enclave/sealdb"
)

// NewSealedDB returns a cmtdb.DB whose values are sealed at rest under the
// running TD's identity (vTPM PolicyOR over supportedProviders).
//
// TDX-on-Linux uses the standard goleveldb storage.OpenFile (flock works on
// regular Linux); the SGX-only noflock workaround does not apply here.
//
// The lazy self-check is invoked here so a misbehaving vTPM is surfaced at
// DB-open time rather than on the first Seal/Unseal call. Subsequent
// sealer-driven Seal/Unseal calls are guarded again by ensureSelfChecked
// inside Backend.Seal/Unseal — the second call is a no-op atomic load.
func (b *Backend) NewSealedDB(name, dir string) (cmtdb.DB, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	return sealdb.New(name, dir, sealerAdapter{b: b}, openTDXStorage)
}

// openTDXStorage adapts goleveldb's storage.OpenFile to the
// sealdb.StorageOpener signature. readOnly=false matches the SGX path.
func openTDXStorage(path string) (storage.Storage, error) {
	return storage.OpenFile(path, false)
}

// sealerAdapter satisfies the enclave.Sealer interface by delegating to the
// Backend's locked Seal/Unseal methods. A wrapper type is used (rather than
// passing *Backend directly) so the Sealer surface stays narrow — the
// Backend exposes additional methods that sealdb has no business calling.
type sealerAdapter struct {
	b *Backend
}

func (s sealerAdapter) Seal(p []byte) ([]byte, error)   { return s.b.Seal(p) }
func (s sealerAdapter) Unseal(c []byte) ([]byte, error) { return s.b.Unseal(c) }
