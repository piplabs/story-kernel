package tdx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// runSelfCheck
// =============================================================================

func TestSelfCheck_AllZeroPCRs_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newBareTestTPM(t)
	mqp := newMockQuoteProvider()
	b := newTestBackendWithProviders(t, tpm, supportedProviders, mqp)

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "is zero or missing")
}

func TestSelfCheck_BootstrapMode_LogsAndProceeds(t *testing.T) {
	t.Parallel()
	// Capture logrus output via a hook.
	hook := newWarnCaptureHook()
	log.AddHook(hook)
	t.Cleanup(func() {
		// Logrus has no public RemoveHook in our version; replacing
		// hooks for the test is too invasive. The hook is process-global
		// but the test asserts behavior, not log line count.
	})

	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	providers := []ProviderPolicy{
		{Name: "default-tpm-pcrs-7-11", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	require.NoError(t, b.runSelfCheck())
	require.True(t, hook.containsBootstrap(), "bootstrap WARN must have been emitted")
}

func TestSelfCheck_OneProviderMatches_Succeeds(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	digest := computeBootstrapDigest(t, tpm, []int{7, 11})
	providers := []ProviderPolicy{
		{Name: "ok", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: digest},
	}
	mqp := newMockQuoteProvider()
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	require.NoError(t, b.runSelfCheck())
}

func TestSelfCheck_NoProviderMatches_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	wrong := bytes.Repeat([]byte{0xCC}, 32)
	providers := []ProviderPolicy{
		{Name: "wrong", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrong},
	}
	mqp := newMockQuoteProvider()
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no supported provider matches")
}

func TestSelfCheck_SelfQuoteMRTDZero_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	// Pre-load a synthesized quote whose MRTD is all zero, keyed under
	// the canary the runSelfCheck path now uses for self-quote.
	canary := []byte("tdx-self-check-canary")
	zeroMRTD := make([]byte, sizeMeasurement)
	q := synthV4TDXQuote(canary, zeroMRTD, defaultTestRTMRs())
	mqp.quotes[hexEncode(canary)] = q

	providers := []ProviderPolicy{
		{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "MRTD is zero")
}

func TestSelfCheck_RawV4_ReportDataCanaryMatches_Succeeds(t *testing.T) {
	t.Parallel()
	// The mock quote provider's default behavior synthesizes a V4 with
	// the caller's reportData embedded. runSelfCheck passes the canary
	// in, so V4.report_data leading bytes equal the canary and the new
	// raw-V4 binding check succeeds.
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	providers := []ProviderPolicy{
		{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	require.NoError(t, b.runSelfCheck())
}

func TestSelfCheck_RawV4_ReportDataMismatch_FailsClosed(t *testing.T) {
	t.Parallel()
	// Pre-load a synthesized quote whose report_data is NOT the canary
	// even though MRTD is non-zero. The new raw-V4 binding check must
	// catch this and fail-closed; before T#37 only MRTD-zero would
	// have been caught.
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	canary := []byte("tdx-self-check-canary")
	wrong := []byte("not-the-canary-bytes")
	q := synthV4TDXQuote(wrong, defaultTestMRTD(), defaultTestRTMRs())
	mqp.quotes[hexEncode(canary)] = q

	providers := []ProviderPolicy{
		{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "direct vendor binding broken",
		"raw-V4 self-check must reject quotes whose report_data leading bytes do not match the canary")
}

func TestSelfCheck_QuoteFailure_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	mqp.err = errors.New("quote provider down")
	providers := []ProviderPolicy{
		{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	b := newTestBackendWithProviders(t, tpm, providers, mqp)

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "self-quote failed")
}

// TestSelfCheck_NoPCRsConfigured_FailsClosed covers the
// "len(pcrSet) == 0" branch in runSelfCheck. A provider with PCRs=nil
// passes the type-system check but yields an empty PCR set after
// uniqueSorted, which the self-check must reject so we don't silently
// run with PCR binding effectively disabled.
func TestSelfCheck_NoPCRsConfigured_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "empty-pcrs", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: nil}, ExpectedDigest: nil},
	}
	mqp := newMockQuoteProvider()
	b := newTestBackendWithProviders(t, tpm, providers, mqp)
	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no PCRs configured")
}

// TestSelfCheck_ReadPCRsFailed_FailsClosed covers the "readPCRs failed"
// branch. We point at a PCR index outside the simulator's capability
// range, which makes go-tpm's TPM2_PCR_Read return an error. The
// simulator supports indexes 0..23; using 99 reliably triggers the
// failure path.
func TestSelfCheck_ReadPCRsFailed_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "bad-pcr-index", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{99}}, ExpectedDigest: nil},
	}
	mqp := newMockQuoteProvider()
	b := newTestBackendWithProviders(t, tpm, providers, mqp)
	err := b.runSelfCheck()
	require.Error(t, err)
	// The error path branches between "read PCRs" failure (go-tpm error)
	// and "is zero or missing" (the simulator returned a zero value for
	// an out-of-range index). Either is acceptable; both come from this
	// test's intent and prove the failure surfaces fail-closed.
	got := err.Error()
	require.True(t,
		bytes.Contains([]byte(got), []byte("read PCRs")) ||
			bytes.Contains([]byte(got), []byte("is zero or missing")),
		"expected read-PCRs failure or zero-PCR rejection, got %q", got)
}

// =============================================================================
// uniqueSorted / formatBootstrapDigests
// =============================================================================

func TestUniqueSorted(t *testing.T) {
	t.Parallel()
	require.Nil(t, uniqueSorted(nil))
	require.Equal(t, []int{1, 2, 3}, uniqueSorted([]int{2, 1, 3}))
	require.Equal(t, []int{1, 2, 3}, uniqueSorted([]int{1, 1, 2, 3, 3, 3}))
	require.Equal(t, []int{7, 11}, uniqueSorted([]int{11, 7, 11, 7}))
}

func TestFormatBootstrapDigests_Format(t *testing.T) {
	t.Parallel()
	providers := []ProviderPolicy{
		{Name: "p1", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}},
	}
	out := formatBootstrapDigests(providers, []string{"deadbeef"})
	require.Contains(t, out, "p1 (PCRs 7,11): 0xdeadbeef")
	// No leading newline; one line for one provider.
	require.NotContains(t, out, "\n\n")
}

// =============================================================================
// logrus capture hook
// =============================================================================

type warnCaptureHook struct {
	entries []*log.Entry
}

func newWarnCaptureHook() *warnCaptureHook { return &warnCaptureHook{} }

func (h *warnCaptureHook) Levels() []log.Level {
	return []log.Level{log.WarnLevel}
}

func (h *warnCaptureHook) Fire(e *log.Entry) error {
	h.entries = append(h.entries, e)
	return nil
}

func (h *warnCaptureHook) containsBootstrap() bool {
	for _, e := range h.entries {
		if bytes.Contains([]byte(e.Message), []byte("TDX backend in bootstrap mode")) {
			return true
		}
	}
	return false
}
