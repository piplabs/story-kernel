package sgx

import (
	"sync"
)

// Test-only helpers that mutate package-private state. The file pattern
// "_test.go" guarantees these are excluded from production builds.

// seedSelfEnclaveInfo installs deterministic codeCommitment and productID
// values into the package-level cache and marks the sync.Once as done so
// subsequent getSelfEnclaveInfo calls return immediately without touching
// the Gramine pseudo-filesystem. Tests that seed the cache MUST defer
// resetSelfEnclaveInfo to restore a fresh state for later tests.
func seedSelfEnclaveInfo(codeCommitment, productID []byte) {
	selfEnclaveOnce.Do(func() {})
	selfEnclaveInfo = &EnclaveInfo{
		ProductID: productID,
		UniqueID:  codeCommitment,
	}
	errSelfEnclave = nil
}

// resetSelfEnclaveInfo clears the cache and replaces the sync.Once so a
// subsequent getSelfEnclaveInfo call re-runs the Gramine pseudo-filesystem
// path. Tests that called seedSelfEnclaveInfo must defer this to avoid
// leaking state into other tests inside the same binary.
func resetSelfEnclaveInfo() {
	selfEnclaveOnce = sync.Once{}
	selfEnclaveInfo = nil
	errSelfEnclave = nil
}

// cachedSelfUniqueID returns the cache's current UniqueID slice (no copy)
// so tests can detect whether a previously-returned getter slice shares
// memory with the cache.
func cachedSelfUniqueID() []byte {
	if selfEnclaveInfo == nil {
		return nil
	}
	return selfEnclaveInfo.UniqueID
}
