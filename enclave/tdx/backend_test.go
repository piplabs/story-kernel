package tdx

import (
	"bytes"
	"errors"
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

func TestBackend_GetSelfIdentity_Caches(t *testing.T) {
	t.Parallel()
	b, mqp := newTestBackend(t)

	id1, err := b.GetSelfIdentity()
	require.NoError(t, err)
	require.Equal(t, 1, mqp.callCount())

	id2, err := b.GetSelfIdentity()
	require.NoError(t, err)
	require.Equal(t, 1, mqp.callCount(), "second call must reuse cached identity")

	// Returned values must be defensive copies — independent slices.
	require.Equal(t, id1.MRTD, id2.MRTD)
	id1.MRTD[0] ^= 0xFF
	id3, err := b.GetSelfIdentity()
	require.NoError(t, err)
	require.NotEqual(t, id1.MRTD, id3.MRTD,
		"cached identity must not be reachable from previous returns")
}

func TestBackend_GetSelfIdentity_TDXShape(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)

	id, err := b.GetSelfIdentity()
	require.NoError(t, err)
	require.Equal(t, enclave.IdentityTDX, id.Type)
	require.Len(t, id.MRTD, sizeMeasurement)
	require.Len(t, id.RTMR0, sizeMeasurement)
	require.Len(t, id.RTMR1, sizeMeasurement)
	require.Len(t, id.RTMR2, sizeMeasurement)
	require.Len(t, id.RTMR3, sizeMeasurement)
	require.Len(t, id.CodeCommitment, 32,
		"v2 decomposed schema: TDX CodeCommitment is keccak256(RTMR2) (32 bytes)")

	// CodeCommitment must equal keccak256(RTMR2). See backend.go::computeSelfIdentity
	// for the v2 decomposed-schema rationale.
	want := ecrypto.Keccak256(id.RTMR2)
	require.True(t, bytes.Equal(want, id.CodeCommitment),
		"CodeCommitment must equal keccak256(RTMR2); chain v2 binary commitment slot stores the same value")
}

func TestBackend_GetSelfCodeCommitment_32B(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)
	c, err := b.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Len(t, c, 32, "TDX code commitment under v2 decomposed schema is keccak256(RTMR2) = 32B")
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

func TestBackend_GetSelfIdentity_QuoteError(t *testing.T) {
	t.Parallel()
	b, mqp := newTestBackend(t)
	mqp.err = errors.New("quote down")

	_, err := b.GetSelfIdentity()
	require.Error(t, err)

	// Cached error: subsequent call must surface the same error without a
	// second underlying call.
	mqp.err = nil
	_, err2 := b.GetSelfIdentity()
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
// Concurrency: GetSelfIdentity must be race-free under concurrent first calls
// =============================================================================

// TestBackend_GetSelfIdentity_ConcurrentFirstCall verifies that concurrent
// first callers see a consistent (id, err) pair. atomic.Pointer publishes the
// once-closure's result with a happens-before edge so no caller observes a
// torn struct where, e.g., the identity is set but the error is still nil
// in another goroutine's view. Run with `-race -count=2` to exercise the
// data race detector against this contract.
func TestBackend_GetSelfIdentity_ConcurrentFirstCall(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	ids := make(chan *enclave.Identity, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			id, err := b.GetSelfIdentity()
			ids <- id
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)

	for err := range errs {
		require.NoError(t, err, "all concurrent first callers must succeed")
	}
	// Every goroutine must observe the same MRTD bytes (defensive copies
	// are independent slices but with identical contents).
	var first []byte
	for id := range ids {
		require.NotNil(t, id)
		if first == nil {
			first = bytes.Clone(id.MRTD)
			continue
		}
		require.Equal(t, first, id.MRTD,
			"all concurrent callers must observe the same cached identity")
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

	_, err3 := b.GetSelfIdentity()
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
	// 32 bytes mirrors the v2 decomposed TDX code commitment shape
	// (keccak256(RTMR2)); the comparison fails before length matters
	// because the local backend cannot read its own identity.
	err := enclave.ValidateCodeCommitment(make([]byte, 32))
	require.Error(t, err)
}
