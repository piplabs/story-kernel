package enclave

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	cmtdb "github.com/cometbft/cometbft-db"
	log "github.com/sirupsen/logrus"
)

// TEE composes the three capability sub-interfaces (Sealer, Quoter,
// Identifier). Components that need only one capability can accept the narrow
// interface instead of a full TEE.
//
// Exactly one backend is registered as the process-wide default per build,
// selected by mutually exclusive cmd/tee_*.go blank imports under build tags
// sgx, tdx, or neither (noop, dev-only).
type TEE interface {
	Sealer
	Quoter
	Identifier

	// NewSealedDB returns a cmtdb.DB whose values are sealed at rest under
	// this TEE's identity.
	NewSealedDB(name, dir string) (cmtdb.DB, error)

	// Backend returns a short identifier for logs and metrics:
	// "sgx" | "tdx" | "noop".
	Backend() string
}

// teeSlot wraps a TEE in a fixed concrete struct so successive
// atomic.Value.Store calls always observe the same dynamic type, even when
// tests swap between different concrete TEE implementations via
// SwapDefault. atomic.Value.Store panics on type mismatch, and we want
// tests to be able to install a fakeBackend and then an errorBackend
// without triggering that panic.
//
// In production, Register is called exactly once with a single concrete
// type, so the wrap is overhead-free.
type teeSlot struct{ tee TEE }

// defaultTEE holds the active TEE backend wrapped in a teeSlot. It is set
// exactly once by the matching backend sub-package's init() via Register,
// triggered by the cmd/tee_*.go blank import that wins under the active
// build tags.
//
// The atomic.Value is defensive: it makes "set after first read" detectable
// in -race builds and prevents a torn pointer load. Callers should treat the
// active backend as effectively immutable after process startup.
var defaultTEE atomic.Value // holds teeSlot

// ErrNoTEE indicates that no real TEE is available (noop backend).
var ErrNoTEE = errors.New("enclave: no TEE backend available (noop build)")

// Register installs t as the active TEE backend. It is called from each
// backend sub-package's init(). Calling Register a second time panics:
// dual-backend builds are nonsensical and indicate a build-tag misconfig.
//
// Production code never calls Register directly. Tests that need to swap the
// active backend use the test-only SwapDefault helper exposed via
// export_test.go.
func Register(t TEE) {
	if t == nil {
		panic("enclave: Register(nil) backend")
	}
	if prev := defaultTEE.Load(); prev != nil {
		slot, ok := prev.(teeSlot)
		if !ok {
			// Unreachable via the public API: Register is the only exported
			// writer and always stores a teeSlot value. This guards against
			// future code that bypasses Register (e.g., a direct
			// atomic.Value.Store in another package), so the corruption
			// surfaces loudly instead of as a confusing type-assertion panic
			// elsewhere.
			panic(fmt.Sprintf("enclave: corrupted defaultTEE — got %T, expected teeSlot "+
				"(some code path bypassed Register and stored a non-teeSlot value)", prev))
		}
		if slot.tee == nil {
			// Unreachable via the public API: Register rejects nil before
			// storing. Same defense-in-depth rationale as the !ok branch.
			panic("enclave: corrupted defaultTEE — teeSlot.tee is nil " +
				"(some code path stored teeSlot{} without going through Register)")
		}
		panic(fmt.Sprintf("enclave: Register called twice (have %q, got %q) — "+
			"two backend sub-packages were imported under conflicting build tags",
			slot.tee.Backend(), t.Backend()))
	}
	defaultTEE.Store(teeSlot{tee: t})
}

// Default returns the active TEE backend or panics if no backend has been
// registered. Panic-on-unregistered is intentional: a binary built without a
// backend tag (and without the noop fallback being imported) cannot safely
// participate in DKG and we want the failure to be loud.
//
// The most common cause of the panic is a misconfigured build: passing both
// `-tags sgx tdx` matches NEITHER cmd/tee_sgx.go (`sgx && !tdx`) nor
// cmd/tee_tdx.go (`tdx && !sgx`) nor cmd/tee_noop.go (`!sgx && !tdx`), so
// no init() runs and no backend gets registered. This is the desired
// fail-closed posture: a dual-backend binary is nonsensical.
func Default() TEE {
	v := defaultTEE.Load()
	if v == nil {
		panic("enclave: no TEE backend registered. Build with -tags sgx for production SGX, " +
			"-tags tdx for production TDX, or build untagged to get the dev-only noop backend " +
			"automatically registered by cmd/tee_noop.go. The combination -tags \"sgx tdx\" " +
			"is intentionally rejected at compile time and lands here.")
	}
	slot, ok := v.(teeSlot)
	if !ok {
		// Unreachable via the public API: Register is the only exported
		// writer and always stores a teeSlot. Mirrors the defensive panic
		// in Register; surfaces corruption from a future
		// atomic.Value.Store bypass loudly with a precise diagnostic.
		panic(fmt.Sprintf("enclave: corrupted defaultTEE — got %T, expected teeSlot "+
			"(some code path bypassed Register and stored a non-teeSlot value)", v))
	}
	if slot.tee == nil {
		// Unreachable via the public API: Register rejects nil before
		// storing. Same defense-in-depth rationale as the !ok branch.
		panic("enclave: corrupted defaultTEE — teeSlot.tee is nil " +
			"(some code path stored teeSlot{} without going through Register)")
	}
	return slot.tee
}

// =============================================================================
// Package-level shim functions: preserve the legacy API by delegating to
// Default(). Existing callers across service/, server/, and store/ continue
// to compile and behave identically.
// =============================================================================

// GetRemoteQuote returns a TEE quote with the given user data embedded.
//
// Wire format depends on the active backend; see Quoter.GetRemoteQuote for
// the full matrix. In short:
//   - SGX backend: raw EREPORT bytes with userData in report_data.
//   - TDX backend: raw V4 quote with userData in V4.report_data.
func GetRemoteQuote(userData []byte) ([]byte, error) {
	return Default().GetRemoteQuote(userData)
}

// GetSelfCodeCommitment returns the running enclave's code commitment.
func GetSelfCodeCommitment() ([]byte, error) {
	return Default().GetSelfCodeCommitment()
}

// ValidateCodeCommitment compares an external code commitment against the
// running enclave's.
func ValidateCodeCommitment(codeCommitment []byte) error {
	return Default().ValidateCodeCommitment(codeCommitment)
}

// SealToFile seals data with the running enclave's sealing key and writes the
// sealed blob to filePath with mode 0600. The write is NOT atomic; concurrent
// readers may observe a partially written file during the write window.
func SealToFile(data []byte, filePath string) error {
	sealed, err := Default().Seal(data)
	if err != nil {
		return fmt.Errorf("failed to seal data: %w", err)
	}

	if err := os.WriteFile(filePath, sealed, 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", filePath, err)
	}
	log.Infof("%s is sealed and written successfully", filePath)

	return nil
}

// UnsealFromFile reads a sealed blob from filePath and unseals it under the
// running enclave's sealing key.
func UnsealFromFile(filePath string) ([]byte, error) {
	sealed, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	plaintext, err := Default().Unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %w", err)
	}

	return plaintext, nil
}

// NewSealedLevelDB returns a cmtdb.DB whose values are sealed at rest under
// the running enclave's identity.
func NewSealedLevelDB(name, dir string) (cmtdb.DB, error) {
	return Default().NewSealedDB(name, dir)
}
