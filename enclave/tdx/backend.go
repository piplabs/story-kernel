package tdx

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

	// The self code commitment is computed lazily on first
	// GetSelfCodeCommitment call. We avoid eager computation in init()
	// because the self-quote path is expensive (one TDX quote round-trip
	// plus parse) and not every binary invocation needs it.
	//
	// selfOnce gates the computeSelfCommitment call; selfResult holds the
	// result + error pair. atomic.Pointer ensures concurrent first
	// callers all observe the same fully-populated struct rather than a
	// torn read where, e.g., commitment is set but err is still nil
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
// (matches the self-commitment caching pattern; see selfResult).
type selfCheckResult struct {
	err error
}

// selfResult bundles the cached self code commitment and any error from the
// computation, so a single atomic.Pointer load gives a consistent view to
// concurrent callers.
type selfResult struct {
	commitment []byte
	err        error
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
	} else if err := extendBinaryMeasurementOnce(b.quoteProvider); err != nil {
		// Self-extend the binary measurement into RTMR3 exactly once per TD
		// lifetime. After this call every subsequent quote carries
		// SHA384(0 || SHA384(elf)) in the RTMR3 slot, which the chain-side
		// TDXValidationHook reads as the binary commitment.
		//
		// A failure here MUST be fail-closed for the whole backend, not just
		// the quote path. If we cannot bind RTMR3 to this binary, sealing
		// stays usable on its own but a malicious or downgraded binary could
		// still drive seal/unseal — defeating the trust model the chain-side
		// hook depends on. Swap *both* the quote provider and the TPM for
		// fail-closed stubs so every TEE operation surfaces the same wrapped
		// error message regardless of which entry point a caller picked.
		log.Errorf("tdx: failed to self-extend RTMR3 with binary measurement: %v", err)
		wrapped := fmt.Errorf("tdx: RTMR3 binary self-extend failed: %w", err)
		b.quoteProvider = failClosedQuoteProvider{err: wrapped}
		b.tpm = failClosedTPM{err: wrapped}
	} else if err := extendPCR12Once(b.tpm); err != nil {
		// Self-extend PCR 12 with SHA-256(kernel ELF) — the supportedProviders
		// policy binds sealing to PCR 12. Initrd-side extension via
		// measure-binary.service is the design intent but fails under the
		// launcher image's systemd hardening; the in-process self-extend
		// is the pragmatic fallback. Trust note: same as RTMR3 — the kernel
		// reads /proc/self/exe (kernel-enforced reflection of the actual
		// loaded ELF) and dm-verity guarantees the on-disk binary matches
		// the measurement chain. A malicious kernel could spoof its own
		// hash here, but dm-verity prevents that scenario.
		log.Errorf("tdx: failed to self-extend PCR 12 with binary measurement: %v", err)
		wrapped := fmt.Errorf("tdx: PCR 12 binary self-extend failed: %w", err)
		b.quoteProvider = failClosedQuoteProvider{err: wrapped}
		b.tpm = failClosedTPM{err: wrapped}
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

// extendPCR12Once extends PCR 12 with SHA-256(running kernel ELF). PCR 12 is
// in supportedProviders' PCRSelection and is required to be non-zero by
// runSelfCheck. The design intent was to have an initrd-side helper run
// tpm2_pcrextend before the kernel binary starts, but the launcher image's
// systemd hardening + tpm2-tools' device TCTI interact badly (the helper
// can't actually open /dev/tpmrm0 from the service's mount namespace). The
// in-process self-extend avoids that systemd plumbing entirely.
//
// Idempotency: the function reads PCR 12 first; if already non-zero, the
// extend is skipped. This handles story-kernel.service Restart=on-failure
// without double-extending. Within a fresh TD boot the very first call
// observes PCR 12 = 0 and extends to SHA256(0...0 || SHA256(elf)); every
// subsequent restart within that boot observes the same non-zero value
// and is a no-op.
//
// Trust note: a malicious binary could lie about its own /proc/self/exe
// hash and extend PCR 12 with an attacker-chosen value. The launcher image
// closes that gap by mounting the rootfs (and thus /usr/local/bin/story-kernel)
// dm-verity read-only — the on-disk ELF is bound to the verity root hash
// embedded in the UKI, and PCR 11 already binds the UKI. So an attacker
// can neither rewrite the binary nor boot a different UKI without
// invalidating PCRs that sealing depends on.
func extendPCR12Once(tpm io.ReadWriter) error {
	const pcrIndex = 12
	// Same bank as the seal policy reads (pcrPolicyHash); the SHA-256
	// crypto digest below must match it.
	sel := tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{pcrIndex}}
	cur, err := tpm2.ReadPCRs(tpm, sel)
	if err != nil {
		return fmt.Errorf("ReadPCRs for PCR %d: %w", pcrIndex, err)
	}
	// Read-first idempotency: skip if PCR 12 is already extended (the
	// launcher's measure-binary service did it, or a prior process did before
	// a restart). PCR 12, like RTMR3, persists for the TD boot; the in-TD vTPM
	// only resets on TD teardown, which is equivalent to a TD restart, so a
	// lone vTPM reset that would defeat this guard cannot happen in normal
	// operation. A double-extend would diverge PCR 12 and lock out unseal.
	if v, ok := cur[pcrIndex]; ok && !isZero(v) {
		log.Infof("tdx: PCR %d already non-zero (%s) — skipping self-extend",
			pcrIndex, hex.EncodeToString(v))
		return nil
	}

	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("open /proc/self/exe for PCR %d extend: %w", pcrIndex, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash /proc/self/exe for PCR %d extend: %w", pcrIndex, err)
	}
	digest := h.Sum(nil)
	if len(digest) != 32 {
		return fmt.Errorf("unexpected SHA-256 digest length %d", len(digest))
	}

	if err := tpm2.PCRExtend(tpm, tpmutil.Handle(pcrIndex), pcrPolicyHash, digest, ""); err != nil {
		return fmt.Errorf("TPM2_PCR_Extend PCR %d: %w", pcrIndex, err)
	}
	log.Infof("tdx: extended PCR %d (sha256) with binary digest %s",
		pcrIndex, hex.EncodeToString(digest))
	return nil
}

// extendBinaryMeasurementOnce binds RTMR3 to this story-kernel binary,
// idempotently. RTMR3 is a 48-byte SHA-384 register the TDX architecture
// reserves for software-defined measurements; on a fresh TD it is zero, and
// the TDX module performs RTMR3 ← SHA384(RTMR3 || data) on every write.
// Committing SHA-384(this ELF) yields RTMR3 = SHA384(0x00…00 || SHA384(elf)),
// which the chain reads as code_commitment = keccak256(RTMR3) — closing the
// gap left by RTMR2 (which measures only the TD initrd + cmdline, not the
// userspace binary loaded after boot).
//
// RTMR3 lives for the whole TD boot — it is NOT reset when this process
// restarts — and its sysfs node is write-only, so we must not blindly
// re-extend: a second extend in the same TD boot would double the register
// (SHA384(SHA384(0||h)||h) ≠ SHA384(0||h)) and break code_commitment.
// We therefore read the current RTMR3 out of a fresh quote and act on it
// (see rtmr3NeedsExtend):
//
//   - zero          → nobody has extended yet; this process does it. Only
//     reachable where story-kernel itself is privileged
//     (non-launcher TDX: docker / bare-metal).
//   - == expected   → RTMR3 already holds exactly this binary's single-extend
//     value: the launcher's privileged rtmr3-extend.service
//     did it (the unprivileged launcher story-kernel user
//     could not write the sysfs node anyway), or a prior
//     process did before a restart. Skip.
//   - anything else → different binary, more than one extend, or tampering.
//     Fail closed.
//
// This mirrors extendPCR12Once's read-first-then-skip guard (PCR 12 is read
// via the TPM; RTMR3 via a quote, since its sysfs node is write-only) and
// makes the in-process extend a safe fallback that defers to the launcher
// service when present.
func extendBinaryMeasurementOnce(qp QuoteProvider) error {
	digest, err := hashSelfBinary()
	if err != nil {
		return err
	}
	cur, err := readSelfRTMR3(qp)
	if err != nil {
		return fmt.Errorf("read RTMR3 before extend: %w", err)
	}
	doExtend, err := rtmr3NeedsExtend(cur, digest)
	if err != nil {
		return err
	}
	if !doExtend {
		log.Infof("tdx: RTMR3 already bound to this binary (%s) — skipping self-extend",
			hex.EncodeToString(cur))
		return nil
	}
	if err := writeRTMRExtend(rtmr3SysfsPath, digest); err != nil {
		return err
	}
	log.Infof("tdx: extended RTMR3 with binary SHA-384 %s", hex.EncodeToString(digest))
	return nil
}

// rtmr3NeedsExtend decides, given the current RTMR3 value and this binary's
// SHA-384(ELF) digest, whether to extend (true), skip (false), or fail. It is
// pure (no I/O) so the three-way decision is unit-testable without a quote,
// sysfs, or /proc.
func rtmr3NeedsExtend(cur, elfDigest []byte) (bool, error) {
	// RTMR3 after exactly one extend from a zeroed register.
	preimage := make([]byte, sizeMeasurement+len(elfDigest)) // first sizeMeasurement bytes stay zero
	copy(preimage[sizeMeasurement:], elfDigest)
	expected := sha512.Sum384(preimage)

	switch {
	case isZero(cur):
		return true, nil
	case bytes.Equal(cur, expected[:]):
		return false, nil
	default:
		return false, fmt.Errorf("tdx: RTMR3 in unexpected state %s (want zero or %s); "+
			"possible double-extend, wrong binary, or tampering",
			hex.EncodeToString(cur), hex.EncodeToString(expected[:]))
	}
}

// readSelfRTMR3 returns the running TD's current RTMR3 by parsing a fresh
// quote. RTMR3's sysfs node is write-only, so a quote is the only way to read
// it back; quote generation needs configfs-tsm file access but not
// CAP_SYS_ADMIN, so it works for the unprivileged launcher story-kernel user.
// report_data is irrelevant here — we only read the measurement registers.
func readSelfRTMR3(qp QuoteProvider) ([]byte, error) {
	quote, err := qp.GetQuote(make([]byte, tdxReportDataSize))
	if err != nil {
		return nil, fmt.Errorf("self-quote: %w", err)
	}
	parsed, err := parseTDXQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("parse self-quote: %w", err)
	}
	return parsed.RTMR3, nil
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

// GetSelfCodeCommitment returns the running TD's 32-byte binary commitment
// keccak256(RTMR3). The value is computed lazily on first call (one TDX
// quote round-trip + parse) and cached; subsequent calls return a defensive
// copy so callers cannot mutate the cache.
//
// Concurrency:
// Concurrent first callers all wait on selfOnce.Do, then read selfResult
// via an atomic load. The atomic.Pointer publishes the writes inside the
// once-closure to every observer; without it, sync.Once alone does not
// guarantee that reads outside the closure see the in-closure writes. -race
// tests (TestBackend_GetSelfCodeCommitment_ConcurrentFirstCall)
// regression-cover this.
func (b *Backend) GetSelfCodeCommitment() ([]byte, error) {
	if err := b.ensureSelfChecked(); err != nil {
		return nil, err
	}
	b.selfOnce.Do(func() {
		commit, err := b.computeSelfCommitment()
		b.selfResult.Store(&selfResult{commitment: commit, err: err})
	})
	r := b.selfResult.Load()
	if r.err != nil {
		return nil, r.err
	}
	return cloneSlice(r.commitment), nil
}

// computeSelfCommitment does the actual quote round-trip + parse and returns
// the 32-byte binary commitment. Extracted from GetSelfCodeCommitment so the
// once-closure stays trivially auditable.
func (b *Backend) computeSelfCommitment() ([]byte, error) {
	quote, err := b.quoteProvider.GetQuote([]byte{0})
	if err != nil {
		return nil, fmt.Errorf("tdx: self-quote failed: %w", err)
	}
	parsed, err := parseTDXQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("tdx: parse self-quote: %w", err)
	}

	// The TDX binary commitment is `keccak256(RTMR3)` under the hybrid
	// identity schema v3. RTMR3 is extended exactly once during TD
	// bootstrap with SHA-384(this kernel ELF) by
	// extendBinaryMeasurementOnce, so its post-extend value reduces to
	// `SHA384(0x00…00 || SHA384(elf))` and is fully determined by the
	// running Go binary. The chain stores `keccak256(RTMR3)` in
	// `EnclaveTypeData.codeCommitment` (whitelisted via
	// DKG.whitelistEnclaveType) and emits the same value in the
	// `Finalized.codeCommitment` slot, so kernel-side signing and
	// chain-side verification line up on the same 32-byte digest with no
	// compression step inside `hashFinalizeDKGResponse`.
	//
	// The platform commitment `keccak256(MRTD || RTMR0 || RTMR1 || RTMR2)`
	// is derived and verified entirely chain-side by the TDXValidationHook
	// against its approvedPlatforms whitelist; the kernel never computes it.
	return ecrypto.Keccak256(parsed.RTMR3), nil
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
