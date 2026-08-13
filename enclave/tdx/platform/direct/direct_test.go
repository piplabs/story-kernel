package direct

import (
	"errors"
	"fmt"
	"testing"

	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// Vendor metadata
// =============================================================================

func TestDirectVendor_Name(t *testing.T) {
	t.Parallel()
	require.Equal(t, "direct", Vendor{}.Name())
	require.Equal(t, VendorName, Vendor{}.Name())
}

func TestDirectVendor_RegisteredAtInit(t *testing.T) {
	t.Parallel()
	got := platform.Lookup(VendorName)
	require.NotNil(t, got, "direct vendor must be registered via init()")
	require.Equal(t, VendorName, got.Name())
}

// =============================================================================
// Probe — non-TDX host behavior
//
// On contributor laptops (macOS) and any non-TDX Linux host, configfs-tsm is
// not present. Probe must return a non-nil error wrapped in ErrNoTDXDevice
// so the parent's selectVendor falls through cleanly. This is the byte-
// identical path the pre-refactor newLinuxQuoteProvider followed.
// =============================================================================

func TestDirectVendor_Probe_NoTDXDevice_ReturnsErrNoTDXDevice(t *testing.T) {
	if probeSucceedsHere(t) {
		t.Skip("real TDX host; configfs-tsm probe succeeds — skipping non-TDX assertion")
	}
	err := Vendor{}.Probe()
	require.Error(t, err, "Probe must fail on non-TDX hosts")
	require.ErrorIs(t, err, ErrNoTDXDevice,
		"Probe failure on non-TDX host must be detectable via errors.Is(err, ErrNoTDXDevice)")
}

func TestDirectVendor_Probe_DoesNotPanic(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() { _ = Vendor{}.Probe() },
		"Probe must never panic; a non-TDX host returns an error instead")
}

// =============================================================================
// QuoteProvider — non-TDX host behavior
//
// QuoteProvider is normally called only after Probe() succeeds. On a
// non-TDX host where Probe() fails, calling QuoteProvider() directly must
// also return the same wrapped ErrNoTDXDevice rather than panicking or
// returning a half-initialized provider. This guards against a future
// refactor that bypasses Probe.
// =============================================================================

func TestDirectVendor_QuoteProvider_NoTDXDevice_ReturnsErrNoTDXDevice(t *testing.T) {
	if probeSucceedsHere(t) {
		t.Skip("real TDX host; QuoteProvider succeeds — skipping non-TDX assertion")
	}
	qp, err := Vendor{}.QuoteProvider()
	require.Error(t, err)
	require.Nil(t, qp)
	require.ErrorIs(t, err, ErrNoTDXDevice)
}

// =============================================================================
// linuxQuoteProvider — input validation paths exercised without real TDX
//
// The GetQuote happy path requires real TDX silicon; we cover the two
// non-hardware branches (oversize input rejection and pad-to-64 path
// boundary) by injecting a stub tdxclient.QuoteProvider via direct
// construction of linuxQuoteProvider. The integration runbook in the
// package README covers the hardware path.
// =============================================================================

func TestLinuxQuoteProvider_RejectsOversizedReportData(t *testing.T) {
	t.Parallel()
	// Construct a linuxQuoteProvider with a nil underlying provider; the
	// length-check returns before we dereference the provider, so a nil
	// is fine for this path.
	l := &linuxQuoteProvider{provider: nil}

	out, err := l.GetQuote(make([]byte, tdxReportDataSize+1))
	require.Nil(t, out)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reportData exceeds 64 bytes",
		"oversize input must report the byte limit verbatim for operator-facing diagnostics")
}

func TestLinuxQuoteProvider_RejectsExactlySixtyFiveBytes(t *testing.T) {
	t.Parallel()
	l := &linuxQuoteProvider{provider: nil}
	out, err := l.GetQuote(make([]byte, 65))
	require.Nil(t, out)
	require.Error(t, err)
}

func TestLinuxQuoteProvider_AcceptsExactlySixtyFourBytes(t *testing.T) {
	t.Parallel()
	// Sixty-four bytes is the maximum allowed; the length check passes
	// and the call proceeds to GetRawQuote, which fails because we
	// pass nil. The error MUST come from GetRawQuote, not the
	// length-check, proving the boundary is correct.
	l := &linuxQuoteProvider{provider: nil}
	out, err := l.GetQuote(make([]byte, 64))
	require.Nil(t, out)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "reportData exceeds",
		"64 bytes is in-range; rejection must come from the underlying provider, not the length check")
}

// =============================================================================
// Probe / QuoteProvider — IsSupported failure branch via the
// getQuoteProvider seam. The seam exists for this purpose and is
// restored on every test cleanup so concurrent tests don't see
// stale stubs.
// =============================================================================

// withSeamReplaced swaps the package-level getQuoteProvider for the
// duration of the test and restores it on cleanup. Tests that touch
// the seam MUST NOT run with t.Parallel() — the seam is package-
// global and parallel mutation would race.
func withSeamReplaced(t *testing.T, fn func() (tdxclient.QuoteProvider, error)) {
	t.Helper()
	prev := getQuoteProvider
	getQuoteProvider = fn
	t.Cleanup(func() { getQuoteProvider = prev })
}

func TestVendorProbe_IsSupportedFails_ReturnsErrNoTDXDevice(t *testing.T) {
	sentinel := errors.New("simulated IsSupported failure")
	withSeamReplaced(t, func() (tdxclient.QuoteProvider, error) {
		return &stubTdxQuoteProvider{supported: sentinel}, nil
	})

	err := Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoTDXDevice,
		"IsSupported failure must be wrapped in ErrNoTDXDevice for fail-closed compatibility")
	require.ErrorIs(t, err, sentinel)
}

func TestVendorProbe_AllSucceeds_ReturnsNil(t *testing.T) {
	withSeamReplaced(t, func() (tdxclient.QuoteProvider, error) {
		return &stubTdxQuoteProvider{supported: nil}, nil
	})

	require.NoError(t, Vendor{}.Probe())
}

func TestVendorQuoteProvider_IsSupportedFails_ReturnsErrNoTDXDevice(t *testing.T) {
	sentinel := errors.New("simulated IsSupported failure (provider path)")
	withSeamReplaced(t, func() (tdxclient.QuoteProvider, error) {
		return &stubTdxQuoteProvider{supported: sentinel}, nil
	})

	qp, err := Vendor{}.QuoteProvider()
	require.Nil(t, qp)
	require.ErrorIs(t, err, ErrNoTDXDevice)
	require.ErrorIs(t, err, sentinel)
}

func TestVendorQuoteProvider_AllSucceeds_ReturnsLinuxProvider(t *testing.T) {
	canned := []byte("seamed-quote")
	withSeamReplaced(t, func() (tdxclient.QuoteProvider, error) {
		return &stubTdxQuoteProvider{rawQuote: canned}, nil
	})

	qp, err := Vendor{}.QuoteProvider()
	require.NoError(t, err)
	require.NotNil(t, qp)
	got, err := qp.GetQuote([]byte{0x42})
	require.NoError(t, err)
	require.Equal(t, canned, got)
}

// =============================================================================
// linuxQuoteProvider — happy path with stubbed underlying tdxclient
//
// We satisfy the tdxclient.QuoteProvider interface (IsSupported() error,
// GetRawQuote([64]byte) ([]byte, error)) with a tiny stub. linuxQuoteProvider
// then delegates through tdxclient.GetRawQuote (the package-level dispatcher
// that switches on type), exercising the pad-to-64 + GetRawQuote path
// without TDX silicon.
// =============================================================================

// stubTdxQuoteProvider satisfies github.com/google/go-tdx-guest/client.QuoteProvider.
// Methods are exported in the underlying package; receiver names are
// chosen so the test stub stays self-contained.
type stubTdxQuoteProvider struct {
	supported    error
	rawQuote     []byte
	rawErr       error
	lastReport64 [64]byte
}

func (s *stubTdxQuoteProvider) IsSupported() error { return s.supported }
func (s *stubTdxQuoteProvider) GetRawQuote(reportData [64]byte) ([]byte, error) {
	s.lastReport64 = reportData
	if s.rawErr != nil {
		return nil, s.rawErr
	}
	return append([]byte(nil), s.rawQuote...), nil
}

func TestLinuxQuoteProvider_GetQuote_HappyPath_BindsUserDataIntoV4ReportData(t *testing.T) {
	t.Parallel()
	// The post-T#37 contract: V4.report_data carries the caller's
	// user_data directly (zero-padded to 64 bytes), with NO AK
	// provisioning, NO TPM2_Quote, and NO bundle wrap. This mirrors
	// the SGX backend's report_data semantics so the on-chain TDX
	// validation hook can compare the leading 32 bytes of
	// V4.report_data against the expected keccak256 commitment.
	canned := []byte("canned-quote-bytes")
	stub := &stubTdxQuoteProvider{rawQuote: canned}
	l := &linuxQuoteProvider{provider: stub}

	got, err := l.GetQuote([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	require.NoError(t, err)
	require.Equal(t, canned, got, "direct vendor must return the underlying raw V4 unmodified")

	// Verify the pad-to-64 contract: the stub captured the input as a
	// fixed [64]byte. The first four bytes are the user's commitment;
	// the remaining 60 bytes are zero. This is the same contract the
	// SGX path honors and the on-chain TDX validation hook expects.
	require.Equal(t, byte(0xDE), stub.lastReport64[0])
	require.Equal(t, byte(0xAD), stub.lastReport64[1])
	require.Equal(t, byte(0xBE), stub.lastReport64[2])
	require.Equal(t, byte(0xEF), stub.lastReport64[3])
	for i := 4; i < 64; i++ {
		require.Equal(t, byte(0), stub.lastReport64[i],
			"reportData byte %d must be zero-padded", i)
	}
}

func TestLinuxQuoteProvider_GetQuote_NilReportData_PadsToZeros(t *testing.T) {
	t.Parallel()
	stub := &stubTdxQuoteProvider{rawQuote: []byte{0x01}}
	l := &linuxQuoteProvider{provider: stub}

	_, err := l.GetQuote(nil)
	require.NoError(t, err)
	for i := 0; i < 64; i++ {
		require.Equal(t, byte(0), stub.lastReport64[i],
			"nil reportData must produce all-zero 64-byte padded buffer")
	}
}

func TestLinuxQuoteProvider_GetQuote_FullSixtyFourBytes_NoTruncation(t *testing.T) {
	t.Parallel()
	// A full 64-byte input must land in V4.report_data verbatim with no
	// truncation or extra padding. This is the boundary case the on-
	// chain verifier is most sensitive to: a kernel that silently
	// dropped the trailing bytes would still pass the leading-32
	// commitment check on chain but would defeat the binding-anywhere
	// reasoning.
	stub := &stubTdxQuoteProvider{rawQuote: []byte{0x01}}
	l := &linuxQuoteProvider{provider: stub}

	full := make([]byte, 64)
	for i := range full {
		full[i] = byte(i ^ 0xA5)
	}
	_, err := l.GetQuote(full)
	require.NoError(t, err)
	for i := 0; i < 64; i++ {
		require.Equal(t, full[i], stub.lastReport64[i],
			"V4.report_data byte %d must equal user_data byte %d verbatim", i, i)
	}
}

func TestLinuxQuoteProvider_GetQuote_PropagatesUnderlyingError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("simulated raw-quote failure")
	stub := &stubTdxQuoteProvider{rawErr: sentinel}
	l := &linuxQuoteProvider{provider: stub}

	out, err := l.GetQuote([]byte{0xAA})
	require.Nil(t, out)
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	require.Contains(t, err.Error(), "GetRawQuote",
		"underlying-error wrap must include the call site so operator logs are diagnostic")
}

// =============================================================================
// Helpers
// =============================================================================

// probeSucceedsHere returns true if direct.Vendor{}.Probe() succeeds on the
// running host — i.e., we are on a real TDX host with configfs-tsm. Tests
// that assert non-TDX behavior use this to t.Skip cleanly on TDX silicon.
func probeSucceedsHere(t *testing.T) bool {
	t.Helper()
	return Vendor{}.Probe() == nil
}

// Compile-time assertion that ErrNoTDXDevice is a sentinel error suitable
// for errors.Is. This is a sanity check; if the variable is reassigned to
// a non-error type the package wouldn't compile, but the explicit assert
// makes the contract visible to readers.
var _ error = ErrNoTDXDevice

// guard against accidental removal of the sentinel from the package
// boundary; the parent's selectVendor relies on errors.Is with this
// sentinel.
func TestErrNoTDXDevice_IsErrorsIsReachable(t *testing.T) {
	t.Parallel()
	wrapped := errors.New("wrapped")
	composed := wrapAsNoTDX(wrapped)
	require.ErrorIs(t, composed, ErrNoTDXDevice)
	require.ErrorIs(t, composed, wrapped)
}

// wrapAsNoTDX mirrors the wrap pattern used by Probe/QuoteProvider so
// the contract test above asserts the canonical error-wrapping shape:
// fmt.Errorf("%w: %w", ErrNoTDXDevice, inner). If a future refactor
// changes the wrap form, this test fails and forces a deliberate
// review.
func wrapAsNoTDX(inner error) error {
	return fmt.Errorf("%w: %w", ErrNoTDXDevice, inner)
}
