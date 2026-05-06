package enclave

// SwapDefault is a test-only helper that swaps in t as the active backend
// and returns a restore function. Production code never calls this.
//
// Implementation note:
// defaultTEE is an atomic.Value that holds a teeSlot wrapper (see tee.go).
// Wrapping every store in the same fixed concrete type lets tests swap
// between different concrete TEE implementations across calls without
// tripping atomic.Value's "type mismatch" panic.
//
// Note: atomic.Value cannot be reset to a nil value once a non-nil value
// has been stored, so the restore is best-effort and assumes prev != nil.
// Tests that run before any Register call should not use SwapDefault.
func SwapDefault(t TEE) (restore func()) {
	prev := defaultTEE.Load()
	defaultTEE.Store(teeSlot{tee: t})
	return func() {
		if prev == nil {
			// Cannot restore to "unset"; leave t in place. Subsequent tests
			// that need a different backend should call SwapDefault again.
			return
		}
		slot, ok := prev.(teeSlot)
		if !ok {
			return
		}
		defaultTEE.Store(slot)
	}
}
