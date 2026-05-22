package tdx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
	// Blank import wires the direct vendor adapter into the platform
	// registry via the sub-package's init().
	_ "github.com/piplabs/story-kernel/enclave/tdx/platform/direct"
)

// Backend is the production TDX backend. It uses go-tdx-guest (configfs-tsm
// direct path, Linux ≥ 6.7) for attestation quotes and a TPM2 PolicyOR over
// per-provider PCR sets (supportedProviders) for sealed storage. The vTPM is
// assumed to be in the TD's TCB (in-TD swtpm). See enclave/tdx/README.md
// for the supported guest interface and the explicit out-of-scope list.
//
// The backend is initialized in this package's init(). Initialization is
// fail-closed: if either the TDX device or the TPM device is unavailable on
// the host, the backend is registered with stub providers that return the
// underlying error from every method, rather than log.Fatal at init time.
// This keeps `make build-tdx` runnable on contributor laptops without TDX
// silicon for unit-test purposes; production hosts get the strict
// runSelfCheck path which DOES log.Fatal on failure.
type Backend struct {
	quoteProvider QuoteProvider
	tpm           TPMDevice
	providers     []ProviderPolicy

	// sealMu serializes TPM operations. /dev/tpmrm0 already serializes at
	// the kernel layer, but holding this lock keeps the wire-format codec
	// state-transition explicit and makes /dev/tpm0 (no kernel-side serial)
	// safe too. Sealed-DB methods hold the same lock when calling
	// tdxSeal/tdxUnseal internally.
	sealMu sync.Mutex

	// Self-identity is computed lazily on first GetSelfIdentity call. We
	// avoid eager computation in init() because the self-quote path is
	// expensive (one TDX quote round-trip plus parse) and not every binary
	// invocation needs it.
	//
	// selfOnce gates the computeSelfIdentity call; selfResult holds the
	// result + error pair. atomic.Pointer ensures concurrent first
	// callers all observe the same fully-populated struct rather than a
	// torn read where, e.g., selfIdentity is set but selfErr is still nil
	// in another goroutine's view. (sync.Once.Do guarantees a single
	// execution but does NOT publish writes from inside the closure to
	// other goroutines that race on the variables read OUTSIDE the
	// closure — hence the atomic.Pointer.)
	selfOnce   sync.Once
	selfResult atomic.Pointer[selfResult]

	// Self-check is run lazily on the first TEE operation rather than
	// eagerly in init(). A transient TPM glitch at process boot (e.g.,
	// vTPM not yet ready while the host is enumerating devices) used to
	// log.Fatal the binary; lazy self-check lets the first operation
	// surface the error without killing the process. Operators can retry,
	// reset the TPM, or bring up the binary in a different posture.
	//
	// Self-check is mandatory on real TDX hosts: it runs once, behind a
	// sync.Once gate, before the first TEE operation completes. There is
	// no environment-variable escape hatch. The fail-closed-stub branches
	// (no TDX device or no TPM) skip the self-check because every method
	// already returns the wrapped initialization error.
	selfCheckOnce sync.Once
	selfCheckRes  atomic.Pointer[selfCheckResult]
}

// selfCheckResult encapsulates the lazy self-check outcome so the
// once-closure publishes a fully-populated struct via atomic.Pointer
// (matches the GetSelfIdentity pattern; see the comment there).
type selfCheckResult struct {
	err error
}

// selfResult bundles the cached self-identity and any error from the
// computation, so a single atomic.Pointer load gives a consistent view to
// concurrent callers.
type selfResult struct {
	id  *enclave.Identity
	err error
}

// Compile-time assertion that Backend satisfies enclave.TEE. The (*Backend)(nil)
// form is used consistently across all backend sub-packages (sgx, tdx, noop).
// TDX uses pointer receivers because Backend holds mutable state (sealMu,
// selfOnce, selfResult, selfCheckOnce, selfCheckRes); a value receiver would
// trigger go vet's copylocks check on every method call.
var _ enclave.TEE = (*Backend)(nil)

// init wires the production TDX backend. On a host without TDX silicon or
// without a TPM device, init registers a backend whose every method returns
// the wrapped initialization error.
//
// init does NOT run the strict self-check eagerly — that runs lazily on
// the first TEE operation via ensureSelfChecked. See Backend.selfCheckOnce
// for the rationale.
func init() {
	b := &Backend{providers: supportedProviders}

	// STORY_TDX_VENDOR is an operator escape hatch documented in
	// enclave/tdx/README.md ("Vendor selection"). Leave it unset on
	// production hosts; the registry auto-detect picks the first vendor
	// whose Probe() succeeds.
	qp, qErr := selectVendor(os.Getenv("STORY_TDX_VENDOR"))
	if qErr != nil {
		log.Errorf("tdx: failed to initialize quote provider: %v", qErr)
		b.quoteProvider = failClosedQuoteProvider{err: qErr}
	} else {
		b.quoteProvider = qp
	}

	tpm, tpmErr := openSystemTPM()
	if tpmErr != nil {
		log.Errorf("tdx: failed to open TPM device: %v", tpmErr)
		b.tpm = failClosedTPM{err: tpmErr}
	} else {
		b.tpm = tpm
	}

	// On stubbed hosts, every method already returns the wrapped init
	// error, so the operator's screen is informative even before the
	// first TEE call. Loud WARN here is the same posture as before.
	_, qIsStub := b.quoteProvider.(failClosedQuoteProvider)
	_, tpmIsStub := b.tpm.(failClosedTPM)
	if qIsStub || tpmIsStub {
		log.Warn("tdx: backend running with fail-closed stubs (not on a TDX host) — " +
			"every TEE operation will return the initialization error. " +
			"This is expected on contributor laptops; not safe for production.")
	}

	enclave.Register(b)
}

// ensureSelfChecked runs the strict startup self-check exactly once on the
// first call from a real-device backend. Stubbed-out backends skip the
// check (their methods already return wrapped errors).
//
// On real TDX hosts:
//   - First TEE operation: runs self-check; if it fails, that operation
//     returns the wrapped error AND every subsequent operation also returns
//     the cached error. The binary stays alive; operators can retry, reset
//     the TPM, or escalate.
//   - Subsequent operations: no self-check overhead (atomic.Pointer load).
//
// This avoids the previous design's log.Fatal-at-init posture which killed
// the binary on transient TPM glitches.
func (b *Backend) ensureSelfChecked() error {
	if _, isStub := b.tpm.(failClosedTPM); isStub {
		return nil
	}
	if _, isStub := b.quoteProvider.(failClosedQuoteProvider); isStub {
		return nil
	}
	b.selfCheckOnce.Do(func() {
		err := b.runSelfCheck()
		b.selfCheckRes.Store(&selfCheckResult{err: err})
	})
	r := b.selfCheckRes.Load()
	if r == nil {
		// Unreachable: selfCheckOnce.Do above always Stores a *selfCheckResult
		// before the Once returns. If this fires, a future refactor broke that
		// invariant — for example, by moving the Store outside the once-closure
		// or by short-circuiting the closure on a stub-bypass path that the
		// stub-skip checks above would normally catch. Panic with a precise
		// diagnostic so the bug is loud, rather than silently letting a
		// nil-deref on r.err crash the goroutine with no context.
		panic("tdx: ensureSelfChecked invariant violated — selfCheckOnce completed " +
			"without storing a selfCheckResult (stub-skip checks above must have " +
			"been bypassed; check whether a new code path stores a non-failClosedTPM/" +
			"non-failClosedQuoteProvider stub for testing without going through Backend)")
	}
	if r.err != nil {
		return fmt.Errorf("tdx: self-check failed: %w", r.err)
	}
	return nil
}

// Backend returns the short identifier "tdx" for logs and metrics.
func (b *Backend) Backend() string { return "tdx" }

// GetRemoteQuote returns a TDX V4/V5 quote with userData embedded as the
// quote's REPORTDATA. userData is padded to 64 bytes with zeros.
func (b *Backend) GetRemoteQuote(userData []byte) ([]byte, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	return b.quoteProvider.GetQuote(userData)
}

// GetSelfIdentity returns the running TD's full native identity. The
// identity is cached on first call; subsequent calls return a defensive
// copy of the cached struct so callers cannot mutate the cache.
//
// Concurrency:
// Concurrent first callers all wait on selfOnce.Do, then read selfResult
// via an atomic load. The atomic.Pointer publishes the writes inside the
// once-closure to every observer; without it, sync.Once alone does not
// guarantee that selfIdentity/selfErr reads outside the closure see the
// in-closure writes. -race tests (TestBackend_GetSelfIdentity_ConcurrentFirstCall)
// regression-cover this.
func (b *Backend) GetSelfIdentity() (*enclave.Identity, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	b.selfOnce.Do(func() {
		id, err := b.computeSelfIdentity()
		b.selfResult.Store(&selfResult{id: id, err: err})
	})
	r := b.selfResult.Load()
	if r.err != nil {
		return nil, r.err
	}
	return cloneIdentity(r.id), nil
}

// computeSelfIdentity does the actual quote round-trip + parse. Extracted
// from GetSelfIdentity so the once-closure stays trivially auditable.
func (b *Backend) computeSelfIdentity() (*enclave.Identity, error) {
	quote, err := b.quoteProvider.GetQuote([]byte{0})
	if err != nil {
		return nil, fmt.Errorf("tdx: self-quote failed: %w", err)
	}
	parsed, err := parseTDXQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("tdx: parse self-quote: %w", err)
	}

	// CodeCommitment for TDX is the 32-byte binary commitment
	// `keccak256(RTMR2)` under the hybrid identity schema. RTMR2
	// carries the kernel binary measurement (initrd + cmdline); the
	// chain stores it in `EnclaveTypeData.codeCommitment` (whitelisted
	// via DKG.whitelistEnclaveType) and emits the same value in the
	// `Finalized.codeCommitment` slot, so kernel-side signing and
	// chain-side verification line up on the same 32-byte digest
	// without any compression step inside `hashFinalizeDKGResponse`.
	//
	// The platform commitment (`keccak256(MRTD || RTMR0 || RTMR1)`)
	// is computed and approved on the chain side by TDXValidationHook
	// against its own `approvedPlatforms` whitelist, and is NOT part
	// of the kernel-side identity — the kernel only signs over the
	// binary half. MRTD/RTMR0/RTMR1 remain populated in `Identity`
	// for diagnostics and for any future host-side platform-commitment
	// exposure.
	//
	// RTMR3 is intentionally excluded because it mutates after boot
	// (DKG sealing state, vTPM extensions); committing to it would
	// make the identity instance-specific rather than
	// kernel-binary-bearing.
	commit := ecrypto.Keccak256(parsed.RTMR2)

	return &enclave.Identity{
		Type:           enclave.IdentityTDX,
		CodeCommitment: commit,
		MRTD:           cloneSlice(parsed.MRTD),
		RTMR0:          cloneSlice(parsed.RTMR0),
		RTMR1:          cloneSlice(parsed.RTMR1),
		RTMR2:          cloneSlice(parsed.RTMR2),
		RTMR3:          cloneSlice(parsed.RTMR3),
	}, nil
}

// GetSelfCodeCommitment returns the running TD's CodeCommitment
// (32-byte `keccak256(RTMR2)` binary commitment; see
// GetSelfIdentity for the v2 decomposed-schema rationale).
func (b *Backend) GetSelfCodeCommitment() ([]byte, error) {
	id, err := b.GetSelfIdentity()
	if err != nil {
		return nil, err
	}
	return cloneSlice(id.CodeCommitment), nil
}

// ValidateCodeCommitment compares an external code commitment to the
// running TD's. Comparison is length-agnostic (bytes.Equal); a 32-byte
// SGX-shaped value submitted to a TDX kernel returns mismatch, not panic.
func (b *Backend) ValidateCodeCommitment(c []byte) error {
	self, err := b.GetSelfCodeCommitment()
	if err != nil {
		return fmt.Errorf("tdx: get self code commitment: %w", err)
	}
	if !bytes.Equal(self, c) {
		return fmt.Errorf("tdx: code commitment mismatch: expected %s got %s",
			hex.EncodeToString(self), hex.EncodeToString(c))
	}
	return nil
}

// Seal encrypts plaintext under the supportedProviders' PolicyOR. Output is
// the wire-format sealed blob defined in seal.go.
func (b *Backend) Seal(plaintext []byte) ([]byte, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	b.sealMu.Lock()
	defer b.sealMu.Unlock()
	return tdxSeal(b.tpm, plaintext, b.providers)
}

// Unseal reverses Seal. Returns an error if the running TPM cannot satisfy
// any of the policy branches encoded in the sealed blob.
func (b *Backend) Unseal(sealed []byte) ([]byte, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	b.sealMu.Lock()
	defer b.sealMu.Unlock()
	return tdxUnseal(b.tpm, sealed, b.providers)
}

// NewSealedDB is implemented in sealdb.go; the method declaration there
// avoids importing cmtdb here.
