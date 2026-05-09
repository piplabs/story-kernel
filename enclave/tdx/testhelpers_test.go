package tdx

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// =============================================================================
// Test helpers
//
// These bypass tdxBackend.init() entirely. They construct *Backend with a
// simulator-backed TPM and a mock quote provider so unit tests can run on
// any host without TDX silicon. The init() path is exercised only by
// hardware-in-the-loop runs documented in the README.
// =============================================================================

// newTestTPM returns a fresh TPM2 simulator with PCRs 7 and 11 extended to
// non-zero values. The startup self-check rejects all-zero PCRs, so tests
// that go through self-check must extend at least the configured PCRs.
func newTestTPM(t *testing.T) TPMDevice {
	t.Helper()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	extendPCR(t, sim, 7, []byte("test-pcr-7"))
	extendPCR(t, sim, 11, []byte("test-pcr-11"))
	return sim
}

// newBareTestTPM returns a simulator with all PCRs zero — for self-check
// failure tests.
func newBareTestTPM(t *testing.T) TPMDevice {
	t.Helper()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	return sim
}

// extendPCR extends the given PCR with sha256(data) using SHA-256 banks.
func extendPCR(t *testing.T, tpm TPMDevice, pcr int, data []byte) {
	t.Helper()
	h := sha256.Sum256(data)
	require.NoError(t, tpm2.PCRExtend(tpm, tpmutil.Handle(pcr), tpm2.AlgSHA256, h[:], ""))
}

// =============================================================================
// Mock quote provider
// =============================================================================

// mockQuoteProvider is a deterministic test double. quotes maps hex(reportData)
// → canned bytes. If a key is missing, Synth returns a freshly synthesized
// V4 quote with the given reportData and the helper-default measurements.
type mockQuoteProvider struct {
	mu     sync.Mutex
	quotes map[string][]byte
	err    error
	// calls records every reportData we were asked for, for invocation
	// counting tests.
	calls [][]byte
}

func newMockQuoteProvider() *mockQuoteProvider {
	return &mockQuoteProvider{quotes: map[string][]byte{}}
}

func (m *mockQuoteProvider) GetQuote(reportData []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, append([]byte(nil), reportData...))
	if m.err != nil {
		return nil, m.err
	}
	if q, ok := m.quotes[hex.EncodeToString(reportData)]; ok {
		return append([]byte(nil), q...), nil
	}
	return synthV4TDXQuote(reportData, defaultTestMRTD(), defaultTestRTMRs()), nil
}

func (m *mockQuoteProvider) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// =============================================================================
// Quote synthesis helpers
// =============================================================================

// defaultTestMRTD returns a deterministic non-zero 48-byte MRTD for tests.
func defaultTestMRTD() []byte {
	b := make([]byte, sizeMeasurement)
	for i := range b {
		b[i] = byte(0xA0 + (i & 0x0F))
	}
	return b
}

// defaultTestRTMRs returns four deterministic non-zero 48-byte RTMRs.
func defaultTestRTMRs() [4][]byte {
	var rtmrs [4][]byte
	for j := 0; j < 4; j++ {
		b := make([]byte, sizeMeasurement)
		for i := range b {
			b[i] = byte((j+1)*0x10 + (i & 0x0F))
		}
		rtmrs[j] = b
	}
	return rtmrs
}

// synthV4TDXQuote constructs a V4 TD10 quote (632 bytes header+body) with
// the supplied reportData (zero-padded to 64), MRTD and RTMRs. All other
// body fields are deterministic non-zero patterns so the parser sees a
// well-formed body.
func synthV4TDXQuote(reportData []byte, mrtd []byte, rtmrs [4][]byte) []byte {
	return synthTDXQuote(4, reportData, mrtd, rtmrs)
}

// synthV5TDXQuote constructs a V5 TD15 quote (696 bytes header+body).
func synthV5TDXQuote(reportData []byte, mrtd []byte, rtmrs [4][]byte) []byte {
	return synthTDXQuote(5, reportData, mrtd, rtmrs)
}

func synthTDXQuote(version uint16, reportData []byte, mrtd []byte, rtmrs [4][]byte) []byte {
	var size int
	switch version {
	case 4:
		size = minQuoteSizeTD10
	case 5:
		size = minQuoteSizeTD15
	default:
		panic("unsupported test quote version")
	}
	buf := make([]byte, size)

	// Header.
	binary.LittleEndian.PutUint16(buf[quoteOffVersion:], version)
	binary.LittleEndian.PutUint32(buf[quoteOffTeeType:], teeTypeTDX)

	// Body fills.
	body := buf[quoteHeaderSizeTDX:]
	copy(body[bodyOffMRTD:bodyOffMRTD+sizeMeasurement], mrtd)
	copy(body[bodyOffRTMR0:bodyOffRTMR0+sizeMeasurement], rtmrs[0])
	copy(body[bodyOffRTMR1:bodyOffRTMR1+sizeMeasurement], rtmrs[1])
	copy(body[bodyOffRTMR2:bodyOffRTMR2+sizeMeasurement], rtmrs[2])
	copy(body[bodyOffRTMR3:bodyOffRTMR3+sizeMeasurement], rtmrs[3])

	// reportData is padded to 64 bytes.
	rd := make([]byte, tdxReportDataSize)
	copy(rd, reportData)
	copy(body[bodyOffReportData:bodyOffReportData+tdxReportDataSize], rd)

	return buf
}

// =============================================================================
// Backend constructors that bypass init()
// =============================================================================

// newTestBackend returns a *Backend wired with the simulator + mock
// quote provider, in bootstrap mode (all ExpectedDigest = nil). The
// backend's runSelfCheck is NOT invoked here; tests that want to exercise
// it call b.runSelfCheck() explicitly.
//
// markSelfCheckPassed is invoked so the lazy ensureSelfChecked guard inside
// every public method is a no-op for these tests — they exercise method
// behavior in isolation, not the self-check pipeline.
func newTestBackend(t *testing.T) (*Backend, *mockQuoteProvider) {
	t.Helper()
	tpm := newTestTPM(t)
	mqp := newMockQuoteProvider()
	b := &Backend{
		quoteProvider: mqp,
		tpm:           tpm,
		providers: []ProviderPolicy{
			{Name: "test-pcrs-7-11", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
		},
	}
	markSelfCheckPassed(b)
	return b, mqp
}

// newTestBackendWithProviders returns a *Backend with caller-supplied
// providers (e.g., populated ExpectedDigest after a measurement). The
// returned backend has its lazy self-check pre-marked as passed; tests that
// want to exercise the self-check itself construct the backend manually.
func newTestBackendWithProviders(t *testing.T, tpm TPMDevice, providers []ProviderPolicy, mqp *mockQuoteProvider) *Backend {
	t.Helper()
	if mqp == nil {
		mqp = newMockQuoteProvider()
	}
	b := &Backend{
		quoteProvider: mqp,
		tpm:           tpm,
		providers:     providers,
	}
	markSelfCheckPassed(b)
	return b
}

// markSelfCheckPassed pre-installs a "self-check succeeded" result on the
// backend so subsequent ensureSelfChecked calls become atomic.Pointer
// no-ops. Tests that want to drive the self-check pipeline construct the
// backend without this helper.
func markSelfCheckPassed(b *Backend) {
	b.selfCheckOnce.Do(func() {
		b.selfCheckRes.Store(&selfCheckResult{err: nil})
	})
}

// onFailClosedHost reports whether the package-level Default appears to be
// running with fail-closed stubs (no real TDX device or no real TPM).
// Detection is by attempting a Quote: stubs return an error, a real
// backend returns bytes. Dispatch tests that assert fail-closed behavior
// use this helper to t.Skip cleanly on real TDX hardware.
func onFailClosedHost(t *testing.T) bool {
	t.Helper()
	_, err := enclave.Default().GetRemoteQuote([]byte{0})
	return err != nil
}
