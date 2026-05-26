package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
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

// rtmr3SysfsPath is the Linux misc-driver sysfs entry that exposes RTMR3's
// SHA-384 measurement register. The `tdx_guest` driver translates a 48-byte
// write here into TDG.MR.RTMR.EXTEND(rtmr=3, data) on the running TD, which
// is irreversible until the TD reboots and is folded into every subsequent
// TDX quote at the RTMR3 slot.
const rtmr3SysfsPath = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

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
	} else if err := extendBinaryMeasurementOnce(); err != nil {
		// Self-extend the binary measurement into RTMR3 exactly once per TD
		// lifetime. After this call every subsequent quote carries
		// SHA384(0 || SHA384(elf)) in the RTMR3 slot, which the chain-side
		// TDXValidationHook reads as the binary commitment.
		//
		// A failure here MUST be fail-closed: if we cannot bind RTMR3 to
		// this binary, downstream code commitments are meaningless. Swap the
		// quote provider for the fail-closed stub so every TEE call returns
		// the wrapped error path with the explanatory message.
		log.Errorf("tdx: failed to self-extend RTMR3 with binary measurement: %v", err)
		b.quoteProvider = failClosedQuoteProvider{err: fmt.Errorf("tdx: RTMR3 binary self-extend failed: %w", err)}
	}

	enclave.Register(b)
}

// hashSelfBinary returns the SHA-384 digest of the running kernel ELF.
// Reads `/proc/self/exe` to defeat path-based spoofing — if a caller has
// already exec'd a tampered binary, the kernel still exposes the actual
// loaded image through the procfs symlink. Returns a 48-byte digest on
// success.
func hashSelfBinary() ([]byte, error) {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("open /proc/self/exe: %w", err)
	}
	defer f.Close()

	h := sha512.New384()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hash /proc/self/exe: %w", err)
	}
	digest := h.Sum(nil)
	if len(digest) != 48 {
		return nil, fmt.Errorf("unexpected SHA-384 digest length %d", len(digest))
	}
	return digest, nil
}

// writeRTMRExtend writes a 48-byte SHA-384 payload to the given sysfs
// measurement path. The `tdx_guest` driver translates the write into a
// TDG.MR.RTMR.EXTEND TDCALL for the corresponding RTMR slot. Extracted
// from extendBinaryMeasurementOnce so the side-effecting step can be
// exercised against a temp file in unit tests without touching the
// production sysfs entry.
func writeRTMRExtend(path string, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("RTMR extend payload must be 48 bytes, got %d", len(digest))
	}
	if err := os.WriteFile(path, digest, 0); err != nil {
		return fmt.Errorf("extend %s: %w", path, err)
	}
	return nil
}

// extendBinaryMeasurementOnce hashes the running kernel ELF and extends it
// into RTMR3 the first time the process boots inside a TD. RTMR3 is a
// 48-byte SHA-384 register reserved by the TDX architecture for software-
// defined measurements; on a fresh TD it is zero-initialised, and the TDX
// module performs RTMR3 ← SHA384(RTMR3 || data) on every write.
//
// By committing the kernel binary measurement here, the resulting RTMR3
// value (SHA384(0x00…00 || SHA384(elf))) is bound to *this* Go binary and
// reflected in every subsequent quote — closing the gap left by RTMR2,
// which only measures TD initrd + cmdline and not the userspace binary
// we run after boot.
//
// Re-extending on the same TD is harmless: writing the same 48-byte
// payload produces the same RTMR3 (since SHA-384 is deterministic and the
// register state has not changed between back-to-back boots — *both*
// start from zero), so the commitment is reboot-stable as long as the
// binary itself is unchanged.
//
// Surfaced errors:
//   - reading `/proc/self/exe` (e.g., FUSE / chroot / pid-1 ns weirdness)
//   - opening `rtmr3:sha384` (kernel without `tdx_guest` driver — caught
//     earlier by the quote-provider stub branch, but defence in depth)
//   - short-write or kernel rejection (TDX module ENODEV, EBUSY, …)
func extendBinaryMeasurementOnce() error {
	digest, err := hashSelfBinary()
	if err != nil {
		return err
	}
	if err := writeRTMRExtend(rtmr3SysfsPath, digest); err != nil {
		return err
	}
	log.Infof("tdx: extended RTMR3 with binary SHA-384 %s", hex.EncodeToString(digest))
	return nil
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
	// `keccak256(RTMR3)` under the hybrid identity schema v3. RTMR3 is
	// extended exactly once during TD bootstrap with SHA-384(this kernel
	// ELF) by extendBinaryMeasurementOnce, so its post-extend value
	// reduces to `SHA384(0x00…00 || SHA384(elf))` and is fully determined
	// by the running Go binary. The chain stores `keccak256(RTMR3)` in
	// `EnclaveTypeData.codeCommitment` (whitelisted via
	// DKG.whitelistEnclaveType) and emits the same value in the
	// `Finalized.codeCommitment` slot, so kernel-side signing and
	// chain-side verification line up on the same 32-byte digest with
	// no compression step inside `hashFinalizeDKGResponse`.
	//
	// Why RTMR3 (and not RTMR2): RTMR2 is fixed at TD boot to the initrd
	// + cmdline measurement (cf. enclave/tdx/README.md "Platforms"). The
	// userspace Go binary is loaded from disk *after* boot and is never
	// reflected in RTMR2 — that register is a property of the boot image,
	// not of this process. RTMR3 is the first software-defined register
	// available to the TD payload, so the kernel claims it at startup.
	//
	// The platform commitment is now `keccak256(MRTD || RTMR0 || RTMR1
	// || RTMR2)` — RTMR2 has moved into the platform half, where it
	// belongs alongside the other boot-time measurements. The hook owns
	// the `approvedPlatforms` whitelist; kernel-side identity does not
	// carry the platform commitment but exposes the constituent fields
	// so external diagnostic tools can compute it.
	commit := ecrypto.Keccak256(parsed.RTMR3)

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
// (32-byte `keccak256(RTMR3)` binary commitment; see
// GetSelfIdentity for the v3 schema rationale).
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
