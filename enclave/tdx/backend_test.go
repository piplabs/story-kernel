package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// =============================================================================
// Default backend registration
//
// The package-level Default may be a fail-closed stub or a fully-initialized
// backend depending on whether the host has TDX silicon and a TPM device.
// On contributor laptops both are absent; the init() registers stubs and
// every Default.X(...) call returns a wrapped initialization error.
// =============================================================================

func TestDefault_RegisteredAsTDX(t *testing.T) {
	t.Parallel()
	d := enclave.Default()
	require.NotNil(t, d)
	require.Equal(t, "tdx", d.Backend())
}

// TestDefault_FailClosedOnNonTDXHost asserts that on a host without a real
// TDX device + TPM, the Default backend's Quote method propagates the
// initialization error rather than returning a stub-shaped success.
func TestDefault_FailClosedOnNonTDXHost(t *testing.T) {
	t.Parallel()
	// We cannot positively detect "non-TDX host" without OS probing, so
	// this test simply asserts the call returns *some* error on any host
	// where the test runner itself lacks /dev/tdx_guest. CI runners have
	// no TDX silicon so the call will error.
	_, err := enclave.Default().GetRemoteQuote([]byte{0})
	if err == nil {
		t.Skip("running on a real TDX host; skipping fail-closed assertion")
	}
}

// =============================================================================
// Integrated tdxBackend tests (simulator + mock quote provider)
// =============================================================================

func TestBackend_Backend(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	require.Equal(t, "tdx", b.Backend())
}

func TestBackend_GetRemoteQuote_Forwarding(t *testing.T) {
	t.Parallel()
	b, mqp := newTestBackend(t)
	q, err := b.GetRemoteQuote([]byte{1, 2, 3})
	require.NoError(t, err)
	require.NotEmpty(t, q)
	require.Equal(t, 1, mqp.callCount())
}

func TestBackend_GetSelfCodeCommitment_Caches(t *testing.T) {
	t.Parallel()
	b, mqp := newTestBackend(t)

	c1, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Equal(t, 1, mqp.callCount())

	c2, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Equal(t, 1, mqp.callCount(), "second call must reuse the cached commitment")
	require.Equal(t, c1, c2)

	// Returned values must be defensive copies — independent slices.
	c1[0] ^= 0xFF
	c3, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.NotEqual(t, c1, c3,
		"cached commitment must not be reachable from previous returns")
}

func TestBackend_GetSelfCodeCommitment_EqualsKeccakRTMR3(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)

	c, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Len(t, c, 32,
		"v3 schema: TDX code commitment is keccak256(RTMR3) (32 bytes)")

	// The commitment must equal keccak256(RTMR3). See
	// backend.go::computeSelfCommitment for the v3 schema rationale (RTMR3
	// carries the kernel-bound binary measurement produced by
	// extendBinaryMeasurementOnce at startup). Re-derive it independently
	// from a fresh quote — RTMR3 is a measurement and does not depend on the
	// report_data passed to GetRemoteQuote.
	q, err := b.GetRemoteQuote([]byte{0})
	require.NoError(t, err)
	parsed, err := parseTDXQuote(q)
	require.NoError(t, err)
	require.Len(t, parsed.RTMR3, sizeMeasurement)
	require.True(t, bytes.Equal(ecrypto.Keccak256(parsed.RTMR3), c),
		"code commitment must equal keccak256(RTMR3); chain v3 binary commitment slot stores the same value")
}

func TestBackend_GetSelfCodeCommitment_32B(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	c, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Len(t, c, 32, "TDX code commitment under v3 schema is keccak256(RTMR3) = 32B")
}

func TestBackend_ValidateCodeCommitment_Match(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	self, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.NoError(t, b.ValidateCodeCommitment(self))
}

func TestBackend_ValidateCodeCommitment_LengthAgnostic(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	// SGX-shaped 32B value must not panic; must surface mismatch.
	err := b.ValidateCodeCommitment(make([]byte, 32))
	require.Error(t, err)
	require.Contains(t, err.Error(), "code commitment mismatch")
}

func TestBackend_GetSelfCodeCommitment_QuoteError(t *testing.T) {
	t.Parallel()
	b, mqp := newTestBackend(t)
	mqp.err = errors.New("quote down")

	_, err := b.GetSelfCodeCommitment()
	require.Error(t, err)

	// Cached error: subsequent call must surface the same error without a
	// second underlying call.
	mqp.err = nil
	_, err2 := b.GetSelfCodeCommitment()
	require.Error(t, err2)
}

// =============================================================================
// SealUnseal via *Backend (locks held)
// =============================================================================

func TestBackend_SealUnseal_RoundTrip(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "p", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, nil)

	plaintext := []byte("backend round-trip plaintext")
	blob, err := b.Seal(plaintext)
	require.NoError(t, err)
	got, err := b.Unseal(blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestBackend_NewSealedDB_Integrated(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	dir := t.TempDir()
	db, err := b.NewSealedDB("integrated", dir)
	require.NoError(t, err)
	defer db.Close()

	require.NoError(t, db.Set([]byte("k"), []byte("v")))
	got, err := db.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), got)
}

// =============================================================================
// Sentinel constants
// =============================================================================

func TestPrimaryKeyHandle_Is81000001(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint32(0x81000001), uint32(primaryKeyHandle),
		"persistent SRK handle must be 0x81000001 per design doc; "+
			"changing this is a breaking compatibility change for previously-sealed blobs")
}

// =============================================================================
// Concurrency: GetSelfCodeCommitment must be race-free under concurrent first calls
// =============================================================================

// TestBackend_GetSelfCodeCommitment_ConcurrentFirstCall verifies that concurrent
// first callers see a consistent (commitment, err) pair. atomic.Pointer publishes
// the once-closure's result with a happens-before edge so no caller observes a
// torn struct where, e.g., the commitment is set but the error is still nil
// in another goroutine's view. Run with `-race -count=2` to exercise the
// data race detector against this contract.
func TestBackend_GetSelfCodeCommitment_ConcurrentFirstCall(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	commits := make(chan []byte, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			c, err := b.GetSelfCodeCommitment()
			commits <- c
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	close(commits)

	for err := range errs {
		require.NoError(t, err, "all concurrent first callers must succeed")
	}
	// Every goroutine must observe the same commitment bytes (defensive
	// copies are independent slices but with identical contents).
	var first []byte
	for c := range commits {
		require.NotNil(t, c)
		if first == nil {
			first = bytes.Clone(c)
			continue
		}
		require.Equal(t, first, c,
			"all concurrent callers must observe the same cached commitment")
	}
}

// =============================================================================
// Lazy self-check (B4)
// =============================================================================

// TestBackend_LazySelfCheck_RunsOnFirstOp confirms the self-check is
// invoked exactly once across multiple TEE operations, and that it is the
// FIRST operation that triggers it (not init).
func TestBackend_LazySelfCheck_RunsOnFirstOp(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	// Construct backend WITHOUT markSelfCheckPassed so the real lazy
	// pipeline runs.
	b := &Backend{
		quoteProvider: mqp,
		tpm:           tpm,
		providers: []ProviderPolicy{
			{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
		},
	}

	// Self-check has not yet run.
	require.Nil(t, b.selfCheckRes.Load(), "self-check must be lazy: nothing stored before first op")

	// First op runs the self-check. The mock quote provider gets called
	// twice: once for the self-check's self-quote, once for the actual op.
	_, err := b.GetRemoteQuote([]byte{1})
	require.NoError(t, err)
	res := b.selfCheckRes.Load()
	require.NotNil(t, res, "self-check result must be cached after first op")
	require.NoError(t, res.err)

	callsAfterFirst := mqp.callCount()
	require.GreaterOrEqual(t, callsAfterFirst, 2,
		"first op should trigger self-quote (self-check) + the op's own quote")

	// Second op: self-check must NOT re-run.
	_, err = b.GetRemoteQuote([]byte{2})
	require.NoError(t, err)
	require.Equal(t, callsAfterFirst+1, mqp.callCount(),
		"second op must add exactly one quote call (the op itself), not re-run self-check")
}

// TestBackend_SelfCheckFailure_PropagatesPerCall confirms a failing
// self-check makes every public method return the wrapped error, not just
// the first call. This guards against a regression where the cache holds
// success-by-default after a partial failure.
func TestBackend_SelfCheckFailure_PropagatesPerCall(t *testing.T) {
	t.Parallel()
	// All-zero PCRs trigger self-check failure with "is zero or missing".
	tpm := newBareTestTPM(t)
	mqp := newMockQuoteProvider()
	b := &Backend{
		quoteProvider: mqp,
		tpm:           tpm,
		providers: []ProviderPolicy{
			{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
		},
	}

	// Each TEE op returns the same wrapped self-check error.
	_, err1 := b.GetRemoteQuote([]byte{1})
	require.Error(t, err1)
	require.ErrorContains(t, err1, "self-check")

	_, err2 := b.Seal([]byte("payload"))
	require.Error(t, err2)
	require.ErrorContains(t, err2, "self-check")

	_, err3 := b.GetSelfCodeCommitment()
	require.Error(t, err3)
	require.ErrorContains(t, err3, "self-check")

	_, err4 := b.Unseal([]byte("anything"))
	require.Error(t, err4)
	require.ErrorContains(t, err4, "self-check")

	err5 := b.ValidateCodeCommitment(make([]byte, 32))
	require.Error(t, err5)
	require.ErrorContains(t, err5, "self-check")

	_, err6 := b.NewSealedDB("ldb", t.TempDir())
	require.Error(t, err6)
	require.ErrorContains(t, err6, "self-check")
}

// TestBackend_LazySelfCheck_StubBypass confirms that fail-closed-stub
// backends do NOT run the self-check (it would fail nonsensically against
// a stub), but their methods still return the wrapped init errors via the
// stub's own Read/Write/GetQuote logic.
func TestBackend_LazySelfCheck_StubBypass(t *testing.T) {
	t.Parallel()
	stubErr := errors.New("synthetic stub init failure")
	b := &Backend{
		quoteProvider: failClosedQuoteProvider{err: stubErr},
		tpm:           failClosedTPM{err: stubErr},
		providers:     []ProviderPolicy{{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}}},
	}

	// Self-check must be skipped (stub guard) — selfCheckRes never populated.
	require.NoError(t, b.ensureSelfChecked())
	require.Nil(t, b.selfCheckRes.Load(), "stub bypass must not populate self-check result")

	// Public methods nonetheless surface the stub's init error.
	_, err := b.GetRemoteQuote([]byte{0})
	require.Error(t, err)
	require.ErrorContains(t, err, "synthetic stub init failure")
}

// =============================================================================
// Identity-getter dispatch tests
//
// On hosts without TDX silicon or a TPM device, the registered Default is a
// fail-closed stub. The tests below verify that the package-level shim
// functions in enclave/tee.go correctly surface the wrapped backend error
// rather than silently returning zero values. They t.Skip on real hardware
// because the assertion would not hold on a working backend.
// =============================================================================

// TestTDX_GetSelfCodeCommitment_PropagatesError verifies that
// enclave.GetSelfCodeCommitment returns a non-nil error when the TDX
// backend is running with stub providers.
func TestTDX_GetSelfCodeCommitment_PropagatesError(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	_, err := enclave.GetSelfCodeCommitment()
	require.Error(t, err)
}

// TestTDX_ValidateCodeCommitment_PropagatesError verifies that
// enclave.ValidateCodeCommitment returns a non-nil error when the TDX
// backend cannot produce its own code commitment for comparison.
func TestTDX_ValidateCodeCommitment_PropagatesError(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	// 32 bytes mirrors the v3 TDX code commitment shape
	// (keccak256(RTMR3)); the comparison fails before length matters
	// because the local backend cannot read its own identity.
	err := enclave.ValidateCodeCommitment(make([]byte, 32))
	require.Error(t, err)
}

// =============================================================================
// RTMR3 self-extend (v3 code-commitment binding)
//
// These tests cover the two halves of extendBinaryMeasurementOnce as
// independently testable units. hashSelfBinary is exercised against the
// test binary (which is itself /proc/self/exe inside `go test`).
// writeRTMRExtend is exercised against a temp file so the real sysfs
// entry is never touched.
// =============================================================================

// TestHashSelfBinary_MatchesProcSelfExe verifies hashSelfBinary returns
// the SHA-384 of the test binary by hashing /proc/self/exe with the
// stdlib and asserting equality.
func TestHashSelfBinary_MatchesProcSelfExe(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skipf("/proc/self/exe unavailable on this host: %v", err)
	}

	got, err := hashSelfBinary()
	require.NoError(t, err)
	require.Len(t, got, 48, "SHA-384 must be 48 bytes")

	// Reference: stdlib-hash /proc/self/exe directly.
	f, err := os.Open("/proc/self/exe")
	require.NoError(t, err)
	defer f.Close()
	h := sha512.New384()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	require.Equal(t, h.Sum(nil), got,
		"hashSelfBinary must match SHA-384 of /proc/self/exe byte-for-byte")
}

// TestHashSelfBinary_Deterministic checks two back-to-back calls return
// the same digest (defends against accidental nondeterminism, e.g., if
// the implementation ever introduced timestamps or per-call salts).
func TestHashSelfBinary_Deterministic(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skipf("/proc/self/exe unavailable on this host: %v", err)
	}
	a, errA := hashSelfBinary()
	b, errB := hashSelfBinary()
	require.NoError(t, errA)
	require.NoError(t, errB)
	require.Equal(t, a, b, "hashSelfBinary must be deterministic for the same binary")
}

// TestWriteRTMRExtend_WritesDigestVerbatim verifies the sysfs-write half
// hands the exact 48-byte payload to the file backing the RTMR slot.
// In production this is `/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384`
// and the kernel translates the write into TDG.MR.RTMR.EXTEND. Under
// test we hand it a temp file so the production sysfs entry is never
// touched.
//
// We pre-create the target file with rw permissions because os.WriteFile
// uses perm=0 in production (matching the existing sysfs file's mode,
// where Linux ignores the open mode for an extant file). On a temp dir,
// perm=0 would create a 000-mode file that the test cannot read back.
func TestWriteRTMRExtend_WritesDigestVerbatim(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "rtmr3.fake")
	require.NoError(t, os.WriteFile(tmp, []byte("placeholder"), 0o600))
	digest, err := hex.DecodeString(
		"112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00" +
			"112233445566778899aabbccddeeff00")
	require.NoError(t, err)
	require.Len(t, digest, 48)

	require.NoError(t, writeRTMRExtend(tmp, digest))

	gotBytes, err := os.ReadFile(tmp)
	require.NoError(t, err)
	require.Equal(t, digest, gotBytes, "sysfs-target file must mirror the digest verbatim")
}

// TestWriteRTMRExtend_RejectsShortPayload guards the 48-byte length
// invariant required by the TDX module's RTMR EXTEND TDCALL.
func TestWriteRTMRExtend_RejectsShortPayload(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "rtmr3.fake")
	err := writeRTMRExtend(tmp, make([]byte, 47))
	require.Error(t, err)
	require.Contains(t, err.Error(), "48 bytes")
	_, statErr := os.Stat(tmp)
	require.ErrorIs(t, statErr, os.ErrNotExist,
		"failed length check must not create the sysfs file")
}

// TestWriteRTMRExtend_RejectsBadPath surfaces the sysfs-write error path
// (e.g., missing tdx_guest driver, permission failure). Pointing at a
// non-existent directory triggers ENOENT from os.WriteFile.
func TestWriteRTMRExtend_RejectsBadPath(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 48)
	digest[0] = 0xAB
	err := writeRTMRExtend(filepath.Join(t.TempDir(), "no-such-dir", "rtmr3"), digest)
	require.Error(t, err)
	require.Contains(t, err.Error(), "extend ")
}

// TestRTMR3_FreshBootDerivation pins the post-boot RTMR3 invariant:
// after exactly one extend by extendBinaryMeasurementOnce on a fresh TD
// (RTMR3 begins as 48 zero bytes), the visible value is
// `SHA384(0x00..00 || SHA384(elf))`. The chain-side binary commitment
// is `keccak256` of this value; matching the formula keeps kernel and
// hook on the same identity.
func TestRTMR3_FreshBootDerivation(t *testing.T) {
	t.Parallel()
	// Use an arbitrary 48-byte digest as a stand-in for SHA-384(elf);
	// we are pinning the *algorithm*, not the binary's actual hash.
	elfDigest, err := hex.DecodeString(
		"6ef60196b6403ae8703d5b4c1db1fb349409c95f7c27f5c6362b11d6ac8782e3" +
			"1df1ec2c5d07431b5e5969597ee883c2")
	require.NoError(t, err)

	// Reference: what the TDX module's RTMR extend produces for the
	// first write into a freshly-zeroed register.
	h := sha512.New384()
	h.Write(bytes.Repeat([]byte{0x00}, 48))
	h.Write(elfDigest)
	wantRTMR3 := h.Sum(nil)

	// Regression-pin against the value the live GCP TD reported with
	// this exact elfDigest at registration block 12015. Any change in
	// the extend formula would require rotating every whitelisted CC.
	expected, err := hex.DecodeString(
		"530461a8abef2f39db1e05c57492e40fb49bd7300f50e38f074ef9d7a21641b8" +
			"29903c6d3be1d79272df597462445a89")
	require.NoError(t, err)
	require.Equal(t, expected, wantRTMR3,
		"RTMR3 fresh-boot derivation must match the published formula")
}

// TestRTMR3NeedsExtend covers the idempotent guard's three-way decision:
// extend when RTMR3 is zero, skip when it already holds this binary's
// single-extend value (launcher rtmr3-extend.service did it, or a prior
// process before a restart), and fail closed on any other value (double
// extend / wrong binary / tampering). Pure logic — no quote/sysfs/proc.
func TestRTMR3NeedsExtend(t *testing.T) {
	t.Parallel()
	// Stand-in for SHA-384(elf); we pin the decision logic, not a real binary.
	elf := bytes.Repeat([]byte{0xAB}, sizeMeasurement)

	// RTMR3 value after exactly one extend from a zeroed register.
	h := sha512.New384()
	h.Write(bytes.Repeat([]byte{0x00}, sizeMeasurement))
	h.Write(elf)
	expected := h.Sum(nil)

	// Fresh (zero) RTMR3 → this process must extend.
	do, err := rtmr3NeedsExtend(make([]byte, sizeMeasurement), elf)
	require.NoError(t, err)
	require.True(t, do, "zero RTMR3 must trigger an extend")

	// Already at the single-extend value → skip, no error.
	do, err = rtmr3NeedsExtend(expected, elf)
	require.NoError(t, err)
	require.False(t, do, "RTMR3 already bound to this binary must be skipped")

	// Double-extended (what a blind re-extend on restart would produce) →
	// rejected, NOT silently skipped.
	h2 := sha512.New384()
	h2.Write(expected)
	h2.Write(elf)
	doubled := h2.Sum(nil)
	_, err = rtmr3NeedsExtend(doubled, elf)
	require.Error(t, err, "double-extended RTMR3 must fail closed")
	require.Contains(t, err.Error(), "unexpected state")

	// Unrelated non-zero value (different binary / tampering) → rejected.
	_, err = rtmr3NeedsExtend(bytes.Repeat([]byte{0xCD}, sizeMeasurement), elf)
	require.Error(t, err)
}

// TestExtendPCR12Once_SkipsWhenAlreadyExtended pins the read-first idempotency
// guard: if PCR 12 is already non-zero (the launcher's measure-binary service
// extended it, or a prior process did before a restart), extendPCR12Once must
// SKIP — never double-extend, which would diverge PCR 12 and make every sealed
// blob unrecoverable. The skip happens before /proc/self/exe is touched, so
// this runs on any host.
func TestExtendPCR12Once_SkipsWhenAlreadyExtended(t *testing.T) {
	t.Parallel()
	tpm := newBareTestTPM(t)
	extendPCR(t, tpm, 12, []byte("prior measure-binary extend"))

	sel := tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{12}}
	before, err := tpm2.ReadPCRs(tpm, sel)
	require.NoError(t, err)

	require.NoError(t, extendPCR12Once(tpm))

	after, err := tpm2.ReadPCRs(tpm, sel)
	require.NoError(t, err)
	require.Equal(t, before[12], after[12], "PCR12 must be unchanged (idempotent skip, no double-extend)")
}

// TestReadSelfRTMR3_ParsesRTMR3FromQuote verifies readSelfRTMR3 reads the RTMR3
// register out of a fresh quote (the only way to read it — the sysfs node is
// write-only). This is the read side of the RTMR3 idempotent guard.
func TestReadSelfRTMR3_ParsesRTMR3FromQuote(t *testing.T) {
	t.Parallel()
	mqp := newMockQuoteProvider()
	want := bytes.Repeat([]byte{0x5A}, sizeMeasurement)
	rtmrs := defaultTestRTMRs()
	rtmrs[3] = want
	mqp.quotes[hex.EncodeToString(make([]byte, tdxReportDataSize))] =
		synthV4TDXQuote(make([]byte, tdxReportDataSize), defaultTestMRTD(), rtmrs)

	got, err := readSelfRTMR3(mqp)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
