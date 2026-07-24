package platform

// Test-only helpers. The functions in this file mutate the global vendor
// registry and are intended exclusively for unit tests that need to
// register fakes alongside the production-init "direct" vendor. They live
// in a production-built file (not a `_test.go`) because the parent
// `enclave/tdx` test files in a different package need to call them.
//
// Production code MUST NOT call either function — the `ForTesting`
// suffix is intentional so reviewers spot misuse during code review, and
// no production code paths reference them.

// SnapshotForTesting captures the current registry state as opaque values
// that RestoreForTesting can re-apply. Pair every call with a t.Cleanup
// that restores the snapshot, otherwise mutations leak across tests.
//
// Snapshot/restore is preferred over a generic Reset hook because tests
// register fakes without losing the production "direct" vendor that
// `enclave/tdx/platform/direct` registers at process init; restoring the
// snapshot brings the registry back to that post-init baseline.
func SnapshotForTesting() (map[string]Vendor, []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	regCopy := make(map[string]Vendor, len(registry))
	for k, v := range registry {
		regCopy[k] = v
	}
	ordCopy := make([]string, len(order))
	copy(ordCopy, order)
	return regCopy, ordCopy
}

// RestoreForTesting overwrites the registry state with the snapshot
// returned by SnapshotForTesting. See SnapshotForTesting's doc for usage.
func RestoreForTesting(reg map[string]Vendor, ord []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]Vendor, len(reg))
	for k, v := range reg {
		registry[k] = v
	}
	order = make([]string, len(ord))
	copy(order, ord)
}
