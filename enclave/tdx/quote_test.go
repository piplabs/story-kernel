package tdx

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// TDX quote provider — failClosedQuoteProvider tests
//
// The production quote provider is constructed by the platform vendor
// registry; for unit tests we rely on the failClosed wrapper, the
// selectVendor tests below, and the parser tests in identity_test.go.
// =============================================================================

func TestFailClosedQuoteProvider_PropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("test sentinel: no TDX device")
	q := failClosedQuoteProvider{err: sentinel}

	out, err := q.GetQuote([]byte("anything"))
	require.Nil(t, out)
	require.ErrorIs(t, err, sentinel)
}

// =============================================================================
// MockQuoteProvider — interface conformance and behavior
// =============================================================================

func TestMockQuoteProvider_DefaultSynth(t *testing.T) {
	t.Parallel()
	mqp := newMockQuoteProvider()

	q, err := mqp.GetQuote([]byte("hello"))
	require.NoError(t, err)
	require.Len(t, q, minQuoteSizeTD10, "default synth is V4 632 bytes")
	require.Equal(t, 1, mqp.callCount())

	parsed, err := parseTDXQuote(q)
	require.NoError(t, err)
	require.Equal(t, defaultTestMRTD(), parsed.MRTD)
}

func TestMockQuoteProvider_InjectedError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("injected")
	mqp := newMockQuoteProvider()
	mqp.err = sentinel

	_, err := mqp.GetQuote(nil)
	require.ErrorIs(t, err, sentinel)
}

func TestMockQuoteProvider_CannedQuote(t *testing.T) {
	t.Parallel()
	canned := synthV5TDXQuote([]byte{1, 2, 3}, defaultTestMRTD(), defaultTestRTMRs())
	mqp := newMockQuoteProvider()
	// Mock returns canned quote when reportData hex matches.
	mqp.quotes[hexEncode([]byte{0xAA})] = canned

	q, err := mqp.GetQuote([]byte{0xAA})
	require.NoError(t, err)
	require.Equal(t, canned, q)

	parsed, err := parseTDXQuote(q)
	require.NoError(t, err)
	require.Equal(t, uint16(5), parsed.Version)
}

// hexEncode is a tiny indirection so the hex package isn't pulled into the
// test file purely for one call site.
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0F]
	}
	return string(out)
}

// =============================================================================
// Quote dispatch test
//
// Verifies that the package-level shim enclave.GetRemoteQuote correctly
// surfaces the wrapped backend error on a fail-closed host. Skips on real
// TDX silicon where the call would succeed.
// =============================================================================

// TestTDX_GetRemoteQuote_PropagatesError checks that enclave.GetRemoteQuote
// returns a non-nil error when the TDX backend's quote provider is a
// fail-closed stub.
func TestTDX_GetRemoteQuote_PropagatesError(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	_, err := enclave.GetRemoteQuote([]byte{0})
	require.Error(t, err)
}

// =============================================================================
// selectVendor — vendor selection algorithm
//
// Tests mutate the platform registry. Each test calls withSnapshotRestore
// to capture the post-init state (which contains the production "direct"
// vendor) and restore it on t.Cleanup. This lets tests register fakes
// freely without polluting later tests.
// =============================================================================

// withSnapshotRestore snapshots the platform registry at test entry and
// restores it on cleanup. Tests that register fakes must call this
// before any platform.Register call.
func withSnapshotRestore(t *testing.T) {
	t.Helper()
	reg, ord := platform.SnapshotForTesting()
	t.Cleanup(func() { platform.RestoreForTesting(reg, ord) })
}

type fakeVendor struct {
	name       string
	probeErr   error
	qp         platform.QuoteProvider
	qpInitErr  error
	probeCount int
	mu         sync.Mutex
}

func (f *fakeVendor) Name() string { return f.name }
func (f *fakeVendor) Probe() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeCount++
	return f.probeErr
}
func (f *fakeVendor) QuoteProvider() (platform.QuoteProvider, error) {
	if f.qpInitErr != nil {
		return nil, f.qpInitErr
	}
	return f.qp, nil
}

type stubQuoteProvider struct{ tag string }

func (q stubQuoteProvider) GetQuote([]byte) ([]byte, error) {
	return []byte("stub:" + q.tag), nil
}

func TestSelectVendor_Override_HitsRegisteredVendor(t *testing.T) {
	withSnapshotRestore(t)
	const name = "ok-vendor"
	v := &fakeVendor{name: name, qp: stubQuoteProvider{tag: name}}
	platform.Register(v)

	qp, err := selectVendor(name)
	require.NoError(t, err)
	require.NotNil(t, qp)
	got, err := qp.GetQuote(nil)
	require.NoError(t, err)
	require.Equal(t, []byte("stub:"+name), got)
}

func TestSelectVendor_Override_UnknownName_FailsLoudly(t *testing.T) {
	withSnapshotRestore(t)
	_, err := selectVendor("definitely-not-a-real-vendor")
	require.Error(t, err)
	require.Contains(t, err.Error(), "STORY_TDX_VENDOR=\"definitely-not-a-real-vendor\" not registered",
		"override miss must report the supplied name verbatim and the available list")
	require.Contains(t, err.Error(), "available:",
		"override miss must enumerate registered vendors so the operator can fix the typo")
}

func TestSelectVendor_Override_PropagatesProbeError(t *testing.T) {
	withSnapshotRestore(t)
	const name = "probe-fail-vendor"
	probeErr := errors.New("simulated probe failure")
	platform.Register(&fakeVendor{name: name, probeErr: probeErr})

	qp, err := selectVendor(name)
	require.Nil(t, qp)
	require.Error(t, err)
	require.ErrorIs(t, err, probeErr,
		"forced-vendor probe failure must propagate the underlying probe error verbatim")
	require.Contains(t, err.Error(), "forced vendor")
}

func TestSelectVendor_Override_DoesNotFallThrough(t *testing.T) {
	// A forced-vendor probe failure must NOT cause selectVendor to try
	// other registered vendors. The operator's explicit override is
	// honored strictly: if it does not work, the call fails.
	withSnapshotRestore(t)
	const failName = "forced-fail"
	const successName = "forced-fall-target"
	probeErr := errors.New("forced probe error")

	failure := &fakeVendor{name: failName, probeErr: probeErr}
	success := &fakeVendor{name: successName, qp: stubQuoteProvider{tag: "should-not-run"}}
	platform.Register(failure)
	platform.Register(success)

	_, err := selectVendor(failName)
	require.Error(t, err, "override path must surface probe error, not silently fall through")
	require.ErrorIs(t, err, probeErr)
	require.Equal(t, 0, success.probeCount,
		"successor vendor must NOT be probed when override is set and named vendor's probe fails")
}

func TestSelectVendor_Override_PropagatesConstructError(t *testing.T) {
	withSnapshotRestore(t)
	const name = "ctor-fail-vendor"
	ctorErr := errors.New("simulated ctor failure")
	platform.Register(&fakeVendor{name: name, qpInitErr: ctorErr})

	qp, err := selectVendor(name)
	require.Nil(t, qp)
	require.Error(t, err)
	require.ErrorIs(t, err, ctorErr)
	require.Contains(t, err.Error(), "construct")
}

func TestSelectVendor_AutoDetect_PicksFirstSucceedingProbe(t *testing.T) {
	// Snapshot the registry, then replace it with two fakes: the first
	// probe-fails, the second probe-succeeds. selectVendor with empty
	// override must walk Order() and pick the second.
	withSnapshotRestore(t)
	platform.RestoreForTesting(map[string]platform.Vendor{}, nil)

	failing := &fakeVendor{name: "first", probeErr: errors.New("nope")}
	winning := &fakeVendor{name: "second", qp: stubQuoteProvider{tag: "winner"}}
	platform.Register(failing)
	platform.Register(winning)

	qp, err := selectVendor("")
	require.NoError(t, err)
	got, err := qp.GetQuote(nil)
	require.NoError(t, err)
	require.Equal(t, []byte("stub:winner"), got)
	require.Equal(t, 1, failing.probeCount, "first vendor's probe must have been attempted")
	require.Equal(t, 1, winning.probeCount, "second vendor's probe must have been attempted")
}

func TestSelectVendor_AutoDetect_RegistrationOrderIsProbeOrder(t *testing.T) {
	// Two vendors both succeed; the first registered must win.
	withSnapshotRestore(t)
	platform.RestoreForTesting(map[string]platform.Vendor{}, nil)

	first := &fakeVendor{name: "alpha", qp: stubQuoteProvider{tag: "alpha"}}
	second := &fakeVendor{name: "beta", qp: stubQuoteProvider{tag: "beta"}}
	platform.Register(first)
	platform.Register(second)

	qp, err := selectVendor("")
	require.NoError(t, err)
	got, _ := qp.GetQuote(nil)
	require.Equal(t, []byte("stub:alpha"), got,
		"first registered vendor wins ties; preserves the upstream-blessed-path-first contract")
	require.Equal(t, 1, first.probeCount)
	require.Equal(t, 0, second.probeCount,
		"once the first vendor wins, no further probes run — short-circuit invariant")
}

func TestSelectVendor_AllProbesFail_ReturnsNoTDXDevice(t *testing.T) {
	// Replace the registry with only failing vendors and assert the
	// no-vendor-found error wraps ErrNoTDXDevice for backwards-
	// compatibility with existing errors.Is callers.
	withSnapshotRestore(t)
	platform.RestoreForTesting(map[string]platform.Vendor{}, nil)

	platform.Register(&fakeVendor{name: "a", probeErr: errors.New("a-fail")})
	platform.Register(&fakeVendor{name: "b", probeErr: errors.New("b-fail")})

	qp, err := selectVendor("")
	require.Nil(t, qp)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoTDXDevice,
		"no-vendor-found must wrap ErrNoTDXDevice so existing errors.Is callers keep working")
	require.Contains(t, err.Error(), "no vendor adapter probe succeeded")
}

func TestSelectVendor_EmptyRegistry_ReturnsNoTDXDevice(t *testing.T) {
	// Defensive case: empty registry. The function must not panic and
	// must return the same wrapped sentinel.
	withSnapshotRestore(t)
	platform.RestoreForTesting(map[string]platform.Vendor{}, nil)

	qp, err := selectVendor("")
	require.Nil(t, qp)
	require.ErrorIs(t, err, ErrNoTDXDevice)
}

// TestSelectVendor_Override_ProbeFailure_WrapsErrNoTDXDevice is the
// regression test for the dual-sentinel issue (audit finding LOW-1).
//
// Vendor sub-packages (e.g., enclave/tdx/platform/direct) define their
// own package-private "no TDX device" sentinel with the same message
// text as tdx.ErrNoTDXDevice but a DIFFERENT pointer (to avoid an
// import cycle). Without explicit re-wrapping in selectVendor, a
// caller using errors.Is(err, tdx.ErrNoTDXDevice) on the override path
// would get a false negative: the chain only contains the vendor's
// local sentinel, which errors.Is does not equate with the parent's.
//
// This test simulates that exact pattern: a fake vendor whose Probe()
// wraps a foreign sentinel (independent *errors.errorString, not
// tdx.ErrNoTDXDevice). selectVendor must guarantee that
// errors.Is(err, tdx.ErrNoTDXDevice) holds on its returned error,
// regardless of what the vendor wrapped internally.
func TestSelectVendor_Override_ProbeFailure_WrapsErrNoTDXDevice(t *testing.T) {
	withSnapshotRestore(t)
	const name = "foreign-sentinel-vendor"
	// Foreign sentinel — independent pointer, same role as
	// direct.ErrNoTDXDevice. Critically, this is NOT tdx.ErrNoTDXDevice.
	foreignNoDeviceSentinel := errors.New("tdx: no TDX device available (configfs-tsm)")
	probeUnderlying := errors.New("simulated underlying configfs-tsm failure")
	probeErr := fmt.Errorf("%w: %w", foreignNoDeviceSentinel, probeUnderlying)
	platform.Register(&fakeVendor{name: name, probeErr: probeErr})

	qp, err := selectVendor(name)
	require.Nil(t, qp)
	require.Error(t, err)

	// The cross-package guarantee: callers matching against the parent
	// package's sentinel must detect the condition.
	require.ErrorIs(t, err, ErrNoTDXDevice,
		"override-path probe failure must wrap tdx.ErrNoTDXDevice so callers using "+
			"errors.Is(err, tdx.ErrNoTDXDevice) detect the condition uniformly across vendors")

	// Underlying chain must remain intact for diagnostics.
	require.ErrorIs(t, err, probeUnderlying,
		"underlying probe error must still be reachable in the wrap chain")
	require.Contains(t, err.Error(), "forced vendor")

	// Sanity: confirm the foreign sentinel is genuinely a different
	// pointer from tdx.ErrNoTDXDevice. If a future refactor merges
	// them, this assertion forces a deliberate test update.
	require.NotSame(t, ErrNoTDXDevice, foreignNoDeviceSentinel,
		"test premise: foreign sentinel must be a distinct pointer from tdx.ErrNoTDXDevice")
}
