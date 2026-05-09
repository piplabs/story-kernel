package tdx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// bundleQuoteProvider — produces real Path-B bundles for self-check tests
//
// Wraps an in-process TPM simulator with a kernel-style RSASSA AK to drive
// the bundle-verification ladder end-to-end. We synth a V4 quote whose
// report_data binds the AK so the load-bearing AK-binding check passes;
// individual tests mutate the V4 / attest / sig before handing the
// bundle back, exercising each fail-closed branch.
//
// In production, only the paravisor vendor emits Path-B bundles (the
// direct vendor returns raw V4 quotes with user_data in V4.report_data),
// so the AK is provisioned at AKHandleParavisor. We mirror the OpenHCL
// paravisor's CreatePrimary+EvictControl ceremony directly because the
// platform package no longer exposes EnsureDirectAK.
// =============================================================================

// bundleQuoteProvider mirrors the production paravisor vendor's
// GetQuote shape by default: it produces an STBN-prefixed bundle whose
// V4 carries SHA256(AK_pub) || zeros (when paravisorMode is false, the
// VendorTagDirect-shaped variant retained here for fail-closed branch
// coverage), or SHA256(VariableData) || zeros (when paravisorMode is
// true, the production paravisor shape). TPM2_Quote signs the caller's
// reportData with the AK at AKHandleParavisor on the in-process
// simulator.
type bundleQuoteProvider struct {
	sim          *simulator.Simulator
	akDER        []byte
	mutateBundle func([]byte) []byte
	mutateMRTD   bool
	// paravisorMode produces a VendorTagParavisor bundle whose
	// RuntimeData carries a JWK envelope (HCLAkPub) and whose
	// V4.report_data binds SHA256(RuntimeData). Used to exercise the
	// vendor-aware AK-binding path of verifySelfBundle.
	paravisorMode bool
}

// provisionParavisorHandleAK provisions the production AKTemplate at
// platform.AKHandleParavisor on the simulator. Mirrors what the OpenHCL
// paravisor does at boot on a paravisor-mediated TDX guest. Used by
// the bundleQuoteProvider so the bundle-mode tests cover the same
// handle the production paravisor vendor reads from.
func provisionParavisorHandleAK(t *testing.T, sim *simulator.Simulator) {
	t.Helper()
	pub := platform.AKTemplate()
	primaryHandle, _, err := tpm2.CreatePrimary(sim, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", pub)
	require.NoError(t, err)
	defer tpm2.FlushContext(sim, primaryHandle)
	require.NoError(t, tpm2.EvictControl(sim, "", tpm2.HandleOwner, primaryHandle, platform.AKHandleParavisor))
}

// newBundleQuoteProvider provisions an AK on a fresh simulator and
// returns a provider. The simulator is closed via t.Cleanup. PCR 7 +
// 11 are pre-extended so the self-check's PCR-non-zero gate passes.
func newBundleQuoteProvider(t *testing.T) *bundleQuoteProvider {
	t.Helper()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	// Extend PCRs so the self-check's "PCR non-zero" guard passes.
	extendPCR(t, sim, 7, []byte("self-check-pcr-7"))
	extendPCR(t, sim, 11, []byte("self-check-pcr-11"))

	provisionParavisorHandleAK(t, sim)

	akDER, err := platform.ReadAKPubDER(sim, platform.AKHandleParavisor)
	require.NoError(t, err)
	return &bundleQuoteProvider{sim: sim, akDER: akDER}
}

// GetQuote synthesizes a V4 quote with AK-bound report_data, runs
// TPM2_Quote with reportData as qualifying_data, marshals the bundle.
// If mutateBundle is set, the bundle is rewritten before return so a
// test can corrupt a single field. If paravisorMode is set, builds a
// paravisor-style bundle: RuntimeData carries a JWK envelope and the
// V4 report_data binds SHA256(RuntimeData) instead of SHA256(AK_pub).
func (p *bundleQuoteProvider) GetQuote(reportData []byte) ([]byte, error) {
	mrtd := defaultTestMRTD()
	if p.mutateMRTD {
		mrtd = make([]byte, sizeMeasurement)
	}

	var (
		v4ReportData = make([]byte, tdxReportDataSize)
		runtimeData  []byte
		vendorTag    = platform.VendorTagDirect
	)
	if p.paravisorMode {
		runtimeData = buildParavisorRuntimeData(p.akDER)
		rtHash := sha256.Sum256(runtimeData)
		copy(v4ReportData[:32], rtHash[:])
		vendorTag = platform.VendorTagParavisor
	} else {
		akHash := sha256.Sum256(p.akDER)
		copy(v4ReportData[:32], akHash[:])
	}
	v4 := synthV4TDXQuote(v4ReportData, mrtd, defaultTestRTMRs())

	attest, sig, err := platform.TPMQuote(p.sim, platform.AKHandleParavisor, reportData)
	if err != nil {
		return nil, err
	}
	bundle, err := platform.MarshalBundle(v4, attest, sig, p.akDER, runtimeData, platform.FlagTPMPresent, vendorTag)
	if err != nil {
		return nil, err
	}
	if p.mutateBundle != nil {
		bundle = p.mutateBundle(bundle)
	}
	return bundle, nil
}

// buildParavisorRuntimeData synthesizes a minimal VariableData JSON
// envelope (RFC 7517 JWK) carrying the supplied AK pub modulus under
// kid="HCLAkPub". Mirrors what the OpenHCL paravisor emits.
func buildParavisorRuntimeData(akDER []byte) []byte {
	mod, err := platform.ExtractRSAModulusFromDER(akDER)
	if err != nil {
		panic(err)
	}
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kid": "HCLAkPub",
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(mod),
			"e":   "AQAB",
		}},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

// =============================================================================
// runSelfCheck — bundle path
// =============================================================================

func TestSelfCheck_Bundle_HappyPath(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	providers := []ProviderPolicy{{
		Name:           "boot",
		PCRSelection:   tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
		ExpectedDigest: nil,
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	require.NoError(t, b.runSelfCheck())
}

func TestSelfCheck_Bundle_HappyPath_Paravisor(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	bqp.paravisorMode = true
	providers := []ProviderPolicy{{
		Name:           "boot",
		PCRSelection:   tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
		ExpectedDigest: nil,
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	require.NoError(t, b.runSelfCheck())
}

func TestSelfCheck_Bundle_ParavisorRuntimeDataTampered_FailsClosed(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	bqp.paravisorMode = true
	bqp.mutateBundle = func(b []byte) []byte {
		parsed, err := platform.UnmarshalBundle(b)
		require.NoError(t, err)
		// Flip a byte in RuntimeData. SHA256(RuntimeData) no longer
		// equals V4.report_data[0:32], so the binding fails.
		tampered := append([]byte(nil), parsed.RuntimeData...)
		tampered[0] ^= 0xFF
		out, err := platform.MarshalBundle(parsed.TdxV4, parsed.TpmAttest, parsed.TpmSig, parsed.AKPub,
			tampered, parsed.Flags, parsed.VendorTag)
		require.NoError(t, err)
		return out
	}
	providers := []ProviderPolicy{{
		Name:         "boot",
		PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "AK binding mismatch")
}

func TestSelfCheck_Bundle_MRTDZero_FailsClosed(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	bqp.mutateMRTD = true
	providers := []ProviderPolicy{{
		Name:         "boot",
		PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "MRTD is zero")
}

func TestSelfCheck_Bundle_AKBindingMismatch_FailsClosed(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	// Replace AKPub bytes inside the bundle with a different (yet valid
	// SPKI) buffer so SHA256 of bundle.AKPub != V4.report_data[0:32].
	bqp.mutateBundle = func(b []byte) []byte {
		parsed, err := platform.UnmarshalBundle(b)
		require.NoError(t, err)
		// Use the platform.MarshalBundle helper to swap AKPub.
		junkAK := make([]byte, len(parsed.AKPub))
		for i := range junkAK {
			junkAK[i] = byte(i ^ 0x55)
		}
		out, err := platform.MarshalBundle(parsed.TdxV4, parsed.TpmAttest, parsed.TpmSig, junkAK,
			parsed.RuntimeData, parsed.Flags, parsed.VendorTag)
		require.NoError(t, err)
		return out
	}
	providers := []ProviderPolicy{{
		Name:         "boot",
		PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	err := b.runSelfCheck()
	require.Error(t, err)
	// Either the AK-binding check or the SPKI parse rejects; both
	// are acceptable fail-closed paths for a junk AK pub.
	got := err.Error()
	require.True(t,
		bytes.Contains([]byte(got), []byte("AK binding mismatch")) ||
			bytes.Contains([]byte(got), []byte("parse AK SPKI")),
		"expected AK-binding or SPKI parse failure, got %q", got)
}

func TestSelfCheck_Bundle_QualifyingDataMismatch_FailsClosed(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	// Replace the bundle's TpmAttest with a freshly-signed quote whose
	// qualifyingData is a different value. Mutating bytes in-place
	// would invalidate the signature; we instead drive a NEW TPM2_Quote
	// with the wrong qualifying_data, attach the resulting attest+sig.
	bqp.mutateBundle = func(b []byte) []byte {
		parsed, err := platform.UnmarshalBundle(b)
		require.NoError(t, err)
		wrongAttest, wrongSig, err := platform.TPMQuote(bqp.sim, platform.AKHandleParavisor, []byte("wrong-canary"))
		require.NoError(t, err)
		out, err := platform.MarshalBundle(parsed.TdxV4, wrongAttest, wrongSig, parsed.AKPub,
			parsed.RuntimeData, parsed.Flags, parsed.VendorTag)
		require.NoError(t, err)
		return out
	}
	providers := []ProviderPolicy{{
		Name:         "boot",
		PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "qualifyingData")
}

func TestSelfCheck_Bundle_BadSignature_FailsClosed(t *testing.T) {
	t.Parallel()
	bqp := newBundleQuoteProvider(t)
	// Flip a byte in the signature blob.
	bqp.mutateBundle = func(b []byte) []byte {
		parsed, err := platform.UnmarshalBundle(b)
		require.NoError(t, err)
		corrupted := append([]byte(nil), parsed.TpmSig...)
		corrupted[len(corrupted)-1] ^= 0xFF
		out, err := platform.MarshalBundle(parsed.TdxV4, parsed.TpmAttest, corrupted, parsed.AKPub,
			parsed.RuntimeData, parsed.Flags, parsed.VendorTag)
		require.NoError(t, err)
		return out
	}
	providers := []ProviderPolicy{{
		Name:         "boot",
		PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}},
	}}
	b := newTestBackendWithProviders(t, bqp.sim, providers, nil)
	b.quoteProvider = bqp

	err := b.runSelfCheck()
	require.Error(t, err)
	require.Contains(t, err.Error(), "RSASSA verify")
}

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
