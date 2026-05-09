package paravisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// Vendor metadata
// =============================================================================

func TestParavisorVendor_Name(t *testing.T) {
	t.Parallel()
	require.Equal(t, "paravisor", Vendor{}.Name())
	require.Equal(t, VendorName, Vendor{}.Name())
}

func TestParavisorVendor_RegisteredAtInit(t *testing.T) {
	t.Parallel()
	got := platform.Lookup(VendorName)
	require.NotNil(t, got, "paravisor vendor must be registered via init()")
	require.Equal(t, VendorName, got.Name())
}

// =============================================================================
// Test fixtures: simulator-backed vTPM + mock IMDS QGS
// =============================================================================

// nopCloseTPM wraps an io.ReadWriter so production defer-close is
// harmless against a test-owned simulator.
type nopCloseTPM struct {
	io.ReadWriter
}

func (nopCloseTPM) Close() error { return nil }

// withSimAndMockQGS sets up:
//   - in-process TPM2 simulator with the AK pre-provisioned at
//     AKHandleParavisor (mimicking the OpenHCL paravisor),
//   - an HCL envelope written to NV 0x01400001 with a TDREPORT whose
//     report_data is SHA256(AK_pub) || zeros(32),
//   - an httptest.Server that returns the V4 we feed it (or a
//     specific status if cfg.statusCode is set).
//
// Returns the simulator (for further customization) and the V4 bytes
// the mock QGS will return on a successful POST.
type qgsConfig struct {
	statusCode int
	emptyQuote bool
	mismatchAK bool // when true, V4.report_data uses a different hash
	zeroAKHash bool // when true, V4.report_data tail bytes are non-zero
	// wrongAKInJWK populates VariableData with a different AK pub, so
	// the modulus comparison after SHA256 binding fails. Exercises the
	// HCLAkPub.n vs bundle.AKPub modulus check.
	wrongAKInJWK bool
}

func withSimAndMockQGS(t *testing.T, cfg qgsConfig) (*simulator.Simulator, []byte) {
	t.Helper()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	// Pre-provision the paravisor AK using the SHARED PSS template at the
	// well-known paravisor handle. The OpenHCL paravisor does this on
	// real paravisor-mediated TDX guests; we stand in.
	provisionParavisorAK(t, sim)

	// Read the AK pub DER so we can compute the expected report_data.
	akDER, err := platform.ReadAKPubDER(sim, platform.AKHandleParavisor)
	require.NoError(t, err)

	// Build the IGVM_REQUEST_DATA.VariableData JSON envelope. On a real
	// paravisor-mediated TDX guest the paravisor emits this and
	// SHA256(VariableData) goes into TDREPORT.report_data and (via QGS)
	// V4.report_data. Test fixture mirrors that flow.
	variableData := buildVariableDataJSON(t, akDER, cfg.wrongAKInJWK)
	rtHash := sha256.Sum256(variableData)

	// Build TDREPORT with report_data set to SHA256(VariableData) at
	// REPORTMAC offset 128 (per HwVmReport.h TDX_REPORTMAC layout).
	tdReport := make([]byte, tdReportSize)
	for i := range tdReport {
		tdReport[i] = byte(i & 0xFF)
	}
	const tdReportReportDataOff = 128
	copy(tdReport[tdReportReportDataOff:tdReportReportDataOff+32], rtHash[:])
	// Ensure trailing 32B of TDREPORT.report_data are zero so the
	// envelope sanity check inside readHCLEnvelope passes.
	for i := tdReportReportDataOff + 32; i < tdReportReportDataOff+64; i++ {
		tdReport[i] = 0
	}

	// Build full HCL envelope: HEADER (32) + HW_ATTESTATION union (1184,
	// of which 1024 is TDREPORT and 160 is union padding) + IGVM_REQUEST_DATA
	// (20) + VariableData. Mirrors the production layout the kernel parses.
	envelopeSize := hclMinFullEnvelopeSize + len(variableData)
	envelope := make([]byte, envelopeSize)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	copy(envelope[hclHeaderSize:hclHeaderSize+tdReportSize], tdReport)
	// HW_ATTESTATION padding (offsets 32+1024 .. 32+1184) stays zero.

	// IGVM_REQUEST_DATA fixed prefix at offset 1216.
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+0:hclIGVMOffset+4], uint32(hclIGVMHeaderSize+len(variableData))) // DataSize
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+4:hclIGVMOffset+8], 1)                                           // Version
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+8:hclIGVMOffset+12], igvmReportTypeTDX)                          // ReportType
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+12:hclIGVMOffset+16], igvmHashTypeSHA256)                        // ReportDataHashType
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+16:hclIGVMOffset+20], uint32(len(variableData)))                 // VariableDataSize
	copy(envelope[hclMinFullEnvelopeSize:], variableData)

	provisionNVHCL(t, sim, envelope)

	// V4 quote — synthetic 632-byte body with paravisor-bound report_data.
	v4 := make([]byte, v4MinSize)
	binary.LittleEndian.PutUint16(v4[0:2], 4) // version
	binary.LittleEndian.PutUint32(v4[v4OffTeeType:v4OffTeeType+4], v4TeeTypeTDX)
	body := v4[v4HeaderSize:]
	if cfg.mismatchAK {
		// Different hash → SHA256(rt) check must fail. We diverge V4
		// from TDREPORT to simulate "QGS routed to a different VM" /
		// "paravisor emitted inconsistent report_data."
		wrong := sha256.Sum256([]byte("wrong-runtime-data"))
		copy(body[v4BodyOffReport:v4BodyOffReport+32], wrong[:])
	} else {
		copy(body[v4BodyOffReport:v4BodyOffReport+32], rtHash[:])
	}
	if cfg.zeroAKHash {
		// Pollute the trailing zero bytes — verifyParavisorAKBinding rejects.
		body[v4BodyOffReport+33] = 0xCC
	}

	// Mock QGS server.
	var v4Returned []byte
	if !cfg.emptyQuote {
		v4Returned = v4
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.statusCode != 0 && cfg.statusCode != http.StatusOK {
			http.Error(w, "QGS error", cfg.statusCode)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Mock the live QGS encoding observed today: URL-safe base64
		// without padding (RawURLEncoding). decodeQuoteBase64 must
		// succeed on this; if a regression switches it to
		// StdEncoding-only the happy-path test will fail.
		_ = json.NewEncoder(w).Encode(imdsTDQuoteResponse{
			Quote: base64.RawURLEncoding.EncodeToString(v4Returned),
		})
	}))
	t.Cleanup(srv.Close)

	prevURL := imdsURL
	imdsURL = srv.URL
	t.Cleanup(func() { imdsURL = prevURL })

	prevTPM := openTPM
	openTPM = func() (io.ReadWriteCloser, error) {
		return nopCloseTPM{ReadWriter: sim}, nil
	}
	t.Cleanup(func() { openTPM = prevTPM })

	return sim, v4
}

// buildVariableDataJSON synthesizes the JSON envelope the paravisor
// emits as IGVM_REQUEST_DATA.VariableData. Real production JSON has
// more keys (HCLEkPub, vm-configuration, user-data); we only need
// HCLAkPub for binding tests. If wrongAK is true, embed a different
// RSA pub so the modulus comparison after SHA256 binding fails —
// exercises verifyParavisorAKBinding's modulus check.
func buildVariableDataJSON(t *testing.T, akPubDER []byte, wrongAK bool) []byte {
	t.Helper()
	var modulus []byte
	if wrongAK {
		// 2048-bit deterministic non-zero modulus, distinct from the
		// AK at AKHandleParavisor.
		modulus = bytes.Repeat([]byte{0xAA}, 256)
	} else {
		var err error
		modulus, err = platform.ExtractRSAModulusFromDER(akPubDER)
		require.NoError(t, err)
	}
	// JWK shape (RFC 7517): "n" is base64url-encoded modulus without padding.
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kid": "HCLAkPub",
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(modulus),
			"e":   "AQAB",
		}},
	}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// provisionParavisorAK creates the same RSA-PSS AK template the
// production helper provisions, but at AKHandleParavisor (the OpenHCL
// paravisor's well-known handle). Uses NewCachedKey to be idempotent.
func provisionParavisorAK(t *testing.T, sim *simulator.Simulator) {
	t.Helper()
	// Mirror the AK template the OpenHCL paravisor pre-provisions on
	// paravisor-mediated TDX guests: RSA-2048-RSASSA-SHA256
	// (PKCS#1 v1.5). Verified empirically with `tpm2_readpublic
	// -c 0x81000003`: scheme=rsassa, hash=sha256.
	pub := platform.AKTemplate()
	primaryHandle, _, err := tpm2.CreatePrimary(sim, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", pub)
	require.NoError(t, err)
	defer tpm2.FlushContext(sim, primaryHandle)

	// Evict to AKHandleParavisor.
	require.NoError(t, tpm2.EvictControl(sim, "", tpm2.HandleOwner, primaryHandle, platform.AKHandleParavisor))
}

// provisionNVHCL defines an NV index in the owner-creatable range
// (0x01000000..0x013FFFFF) and writes the HCL envelope to it. The
// simulator refuses NVDefineSpace under HandleOwner for platform-
// creator indexes (0x01400000+), where the real paravisor NV lives.
// The test seam (hclNVIndex variable in paravisor.go) is overridden
// here so the production read path exercises the same NVReadEx code
// on the owner-range index. The NVReadEx code is name-alg- and range-
// agnostic; we don't lose coverage by relocating.
//
// We use NVDefineSpaceEx so we can pin NameAlg=SHA256; the helper
// NVDefineSpace hard-codes SHA1, which the in-process simulator
// rejects on more recent builds with TPM_RC_SIZE on the public
// area.
func provisionNVHCL(t *testing.T, sim *simulator.Simulator, envelope []byte) {
	t.Helper()
	const testNVIndex tpmutil.Handle = 0x01000001
	prev := hclNVIndex
	hclNVIndex = testNVIndex
	t.Cleanup(func() { hclNVIndex = prev })

	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	require.NoError(t, tpm2.NVDefineSpace(
		sim, tpm2.HandleOwner, testNVIndex, "", "", nil, attr, uint16(len(envelope)),
	))
	// NVWrite single-shot supports up to ~1024 bytes on the simulator;
	// the HCL envelope is 1056 bytes (32B header + 1024B TDREPORT). Chunk
	// the write so each call stays under the buffer limit.
	const chunk = 512
	for off := 0; off < len(envelope); off += chunk {
		end := off + chunk
		if end > len(envelope) {
			end = len(envelope)
		}
		require.NoError(t, tpm2.NVWrite(sim, tpm2.HandleOwner, testNVIndex, "", envelope[off:end], uint16(off)))
	}
}

// =============================================================================
// Probe
// =============================================================================

func TestParavisorVendor_Probe_Success(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{})
	require.NoError(t, Vendor{}.Probe())
}

func TestParavisorVendor_Probe_NoTPM(t *testing.T) {
	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) {
		return nil, errIO("no /dev/tpmrm0")
	}
	t.Cleanup(func() { openTPM = prev })

	err := Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoParavisor)
}

func TestParavisorVendor_Probe_NVReadFails(t *testing.T) {
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	// No NV index defined → NVRead fails.
	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) { return nopCloseTPM{ReadWriter: sim}, nil }
	t.Cleanup(func() { openTPM = prev })

	err = Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoParavisor)
}

func TestParavisorVendor_Probe_HCLBadMagic(t *testing.T) {
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAK(t, sim)

	envelope := make([]byte, hclEnvelopeMin)
	// Bad magic at offset 0.
	binary.LittleEndian.PutUint32(envelope[0:4], 0xDEADBEEF)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	provisionNVHCL(t, sim, envelope)

	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) { return nopCloseTPM{ReadWriter: sim}, nil }
	t.Cleanup(func() { openTPM = prev })

	err = Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoParavisor)
	require.Contains(t, err.Error(), "magic")
}

func TestParavisorVendor_Probe_HCLBadVersion(t *testing.T) {
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAK(t, sim)

	envelope := make([]byte, hclEnvelopeMin)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], 99) // bad version
	provisionNVHCL(t, sim, envelope)

	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) { return nopCloseTPM{ReadWriter: sim}, nil }
	t.Cleanup(func() { openTPM = prev })

	err = Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoParavisor)
	require.Contains(t, err.Error(), "version")
}

func TestParavisorVendor_Probe_IMDSUnreachable(t *testing.T) {
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAK(t, sim)

	envelope := make([]byte, hclEnvelopeMin)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	provisionNVHCL(t, sim, envelope)

	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) { return nopCloseTPM{ReadWriter: sim}, nil }
	t.Cleanup(func() { openTPM = prev })

	prevURL := imdsURL
	imdsURL = "http://127.0.0.1:1" // unreachable port
	t.Cleanup(func() { imdsURL = prevURL })

	err = Vendor{}.Probe()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoParavisor)
}

// =============================================================================
// QuoteProvider construction
// =============================================================================

func TestParavisorVendor_QuoteProvider_RefusesRawV4(t *testing.T) {
	t.Setenv(envBundleMode, bundleModeRawV4)
	qp, err := Vendor{}.QuoteProvider()
	require.Nil(t, qp)
	require.ErrorIs(t, err, ErrParavisorBundleModeRawV4)
}

func TestParavisorVendor_QuoteProvider_DefaultMode(t *testing.T) {
	qp, err := Vendor{}.QuoteProvider()
	require.NoError(t, err)
	require.NotNil(t, qp)
}

// =============================================================================
// GetQuote — happy path
// =============================================================================

func TestParavisorGetQuote_HappyPath_ReturnsBundle(t *testing.T) {
	sim, _ := withSimAndMockQGS(t, qgsConfig{})

	q := &paravisorQuoteProvider{}
	bundle, err := q.GetQuote([]byte("user-data-xyz"))
	require.NoError(t, err)
	require.True(t, platform.HasBundleMagic(bundle))

	parsed, err := platform.UnmarshalBundle(bundle)
	require.NoError(t, err)
	require.Equal(t, platform.VendorTagParavisor, parsed.VendorTag)
	require.True(t, parsed.HasTPM())
	require.NotEmpty(t, parsed.AKPub)

	// Confirm AK pub matches what the simulator holds.
	akDER, err := platform.ReadAKPubDER(sim, platform.AKHandleParavisor)
	require.NoError(t, err)
	require.Equal(t, akDER, parsed.AKPub)
}

func TestParavisorGetQuote_RefusesRawV4Mode(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{})
	t.Setenv(envBundleMode, bundleModeRawV4)

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.ErrorIs(t, err, ErrParavisorBundleModeRawV4)
}

func TestParavisorGetQuote_ConcurrentEnsureAKPub(t *testing.T) {
	// Verifies akMu serializes concurrent ensureAKPub callers so the
	// cache assignment is race-free. We hold the simulator under a
	// shared lock because the simulator ReadWriter is single-threaded
	// (production /dev/tpmrm0 is serialized by the kernel resource
	// manager); the test invariant is that even in that constrained
	// case, the akPubDER write is not torn and all goroutines see the
	// same DER.
	sim, _ := withSimAndMockQGS(t, qgsConfig{})

	var simMu sync.Mutex
	lockedRW := lockedReadWriter{rw: sim, mu: &simMu}

	q := &paravisorQuoteProvider{}
	const n = 8
	results := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = q.ensureAKPub(lockedRW)
		}()
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i], "goroutine %d", i)
		require.NotEmpty(t, results[i], "goroutine %d empty DER", i)
		if i > 0 {
			require.Equal(t, results[0], results[i], "goroutine %d DER diverged", i)
		}
	}
}

// lockedReadWriter wraps an io.ReadWriter with a mutex so concurrent
// callers do not corrupt the underlying simulator state. Mirrors what
// /dev/tpmrm0 does in production (kernel resource manager serializes
// TPM commands).
type lockedReadWriter struct {
	rw io.ReadWriter
	mu *sync.Mutex
}

func (l lockedReadWriter) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rw.Read(p)
}

func (l lockedReadWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rw.Write(p)
}

func TestParavisorGetQuote_OversizedReportData(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{})
	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote(make([]byte, 65))
	require.Error(t, err)
}

func TestDecodeQuoteBase64_AllFlavors(t *testing.T) {
	t.Parallel()
	// Regression guard: live QGS endpoints return URL-safe base64
	// without padding. Pre-2026-05-09 kernel built with StdEncoding
	// only and failed self-check on the live IMDS endpoint with
	// "illegal base64 data at input byte 21" (the first '_' or '-'
	// character).
	want := []byte("test-payload-with-special-bytes-\xff\x00\x80\x7f\xfe")
	cases := []struct {
		name string
		enc  *base64.Encoding
	}{
		{"RawURLEncoding (live QGS format)", base64.RawURLEncoding},
		{"URLEncoding (URL-safe with padding)", base64.URLEncoding},
		{"RawStdEncoding (standard without padding)", base64.RawStdEncoding},
		{"StdEncoding (standard with padding)", base64.StdEncoding},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeQuoteBase64(tc.enc.EncodeToString(want))
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestDecodeQuoteBase64_RejectsGarbage(t *testing.T) {
	t.Parallel()
	_, err := decodeQuoteBase64("not!!!base64@@@")
	require.Error(t, err)
}

// =============================================================================
// GetQuote — failure paths
// =============================================================================

func TestParavisorGetQuote_QGSReturnsServerError(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{statusCode: http.StatusInternalServerError})

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 500")
}

func TestParavisorGetQuote_QGSReturnsEmptyQuote(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{emptyQuote: true})

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty quote")
}

func TestParavisorGetQuote_HCLBadMagic_FailsClosed(t *testing.T) {
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })
	provisionParavisorAK(t, sim)

	// Wrong magic in the envelope.
	envelope := make([]byte, hclEnvelopeMin)
	binary.LittleEndian.PutUint32(envelope[0:4], 0xCAFEBABE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	provisionNVHCL(t, sim, envelope)

	prev := openTPM
	openTPM = func() (io.ReadWriteCloser, error) { return nopCloseTPM{ReadWriter: sim}, nil }
	t.Cleanup(func() { openTPM = prev })

	q := &paravisorQuoteProvider{}
	_, err = q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "magic")
}

func TestParavisorGetQuote_AKBindingMismatch(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{mismatchAK: true})

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrParavisorAKBindingMismatch)
}

func TestParavisorGetQuote_AKBinding_NonZeroTrailing(t *testing.T) {
	withSimAndMockQGS(t, qgsConfig{zeroAKHash: true})

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrParavisorAKBindingMismatch)
}

func TestParavisorGetQuote_AKModulusMismatch(t *testing.T) {
	// VariableData embeds a different RSA pub from the AK in the vTPM.
	// SHA256(VariableData) match holds (paravisor signed it), but the
	// modulus comparison in verifyParavisorAKBinding rejects: this is
	// the load-bearing check that prevents AK substitution attacks.
	withSimAndMockQGS(t, qgsConfig{wrongAKInJWK: true})

	q := &paravisorQuoteProvider{}
	_, err := q.GetQuote([]byte("x"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrParavisorAKBindingMismatch)
	require.Contains(t, err.Error(), "HCLAkPub.n != bundle.AKPub modulus")
}

// =============================================================================
// platform.ExtractHCLAkPubModulus / platform.ExtractRSAModulusFromDER direct units
// =============================================================================

func TestExtractHCLAkPubModulus_HappyPath(t *testing.T) {
	t.Parallel()
	mod := bytes.Repeat([]byte{0xBE}, 256)
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kid": "HCLAkPub", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(mod),
			"e": "AQAB",
		}},
	}
	js, err := json.Marshal(doc)
	require.NoError(t, err)
	got, err := platform.ExtractHCLAkPubModulus(js)
	require.NoError(t, err)
	require.Equal(t, mod, got)
}

func TestExtractHCLAkPubModulus_LeadingZeroStripped(t *testing.T) {
	t.Parallel()
	// Some encoders prepend 0x00 to RSA modulus (sign-bit safety on
	// signed-int representations). The helper strips it so byte-equal
	// compare against platform.ExtractRSAModulusFromDER is consistent.
	mod := append([]byte{0x00}, bytes.Repeat([]byte{0xBE}, 256)...)
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kid": "HCLAkPub", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(mod),
		}},
	}
	js, err := json.Marshal(doc)
	require.NoError(t, err)
	got, err := platform.ExtractHCLAkPubModulus(js)
	require.NoError(t, err)
	require.Equal(t, mod[1:], got)
}

func TestExtractHCLAkPubModulus_PaddedURLAcceptable(t *testing.T) {
	t.Parallel()
	mod := bytes.Repeat([]byte{0xCC}, 257) // odd length triggers padding
	doc := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kid": "HCLAkPub", "kty": "RSA",
			"n": base64.URLEncoding.EncodeToString(mod), // padded variant
		}},
	}
	js, err := json.Marshal(doc)
	require.NoError(t, err)
	_, err = platform.ExtractHCLAkPubModulus(js)
	require.NoError(t, err)
}

func TestExtractHCLAkPubModulus_BadJSON(t *testing.T) {
	t.Parallel()
	_, err := platform.ExtractHCLAkPubModulus([]byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse VariableData JSON")
}

func TestExtractHCLAkPubModulus_NoHCLAkPub(t *testing.T) {
	t.Parallel()
	js := []byte(`{"keys":[{"kid":"OtherKey","kty":"RSA","n":"AAAA"}]}`)
	_, err := platform.ExtractHCLAkPubModulus(js)
	require.Error(t, err)
	require.Contains(t, err.Error(), "HCLAkPub entry not found")
}

func TestExtractHCLAkPubModulus_WrongKty(t *testing.T) {
	t.Parallel()
	js := []byte(`{"keys":[{"kid":"HCLAkPub","kty":"EC","n":"AAAA"}]}`)
	_, err := platform.ExtractHCLAkPubModulus(js)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected RSA")
}

func TestExtractHCLAkPubModulus_EmptyN(t *testing.T) {
	t.Parallel()
	js := []byte(`{"keys":[{"kid":"HCLAkPub","kty":"RSA","n":""}]}`)
	_, err := platform.ExtractHCLAkPubModulus(js)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is empty")
}

func TestExtractHCLAkPubModulus_BadBase64(t *testing.T) {
	t.Parallel()
	js := []byte(`{"keys":[{"kid":"HCLAkPub","kty":"RSA","n":"not!!!base64@@@"}]}`)
	_, err := platform.ExtractHCLAkPubModulus(js)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode HCLAkPub.n")
}

func TestExtractRSAModulusFromDER_BadDER(t *testing.T) {
	t.Parallel()
	_, err := platform.ExtractRSAModulusFromDER([]byte("not der"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "ParsePKIXPublicKey")
}

// =============================================================================
// readHCLEnvelope edge cases (short envelope, IGVM consistency)
// =============================================================================

func TestReadHCLEnvelope_ShortEnvelopeReturnsTDReportOnly(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	// Build a "legacy" short envelope (no IGVM_REQUEST_DATA). The
	// reader tolerates this for backward-compat with pre-Path-B
	// captures and SNP images that store runtime data elsewhere.
	envelope := make([]byte, hclEnvelopeMin)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	provisionNVHCL(t, sim, envelope)

	got, err := readHCLEnvelope(sim)
	require.NoError(t, err)
	require.Len(t, got.TDReport, tdReportSize)
	require.Empty(t, got.VariableData, "short envelope must yield nil VariableData")
}

func TestReadHCLEnvelope_IGVMUnsupportedVersion(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	envelope := make([]byte, hclMinFullEnvelopeSize+8)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+0:hclIGVMOffset+4], 100) // DataSize non-zero
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+4:hclIGVMOffset+8], 99)  // unsupported Version
	provisionNVHCL(t, sim, envelope)

	_, err = readHCLEnvelope(sim)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IGVM_REQUEST_DATA.Version")
}

func TestReadHCLEnvelope_IGVMUnsupportedReportType(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	envelope := make([]byte, hclMinFullEnvelopeSize+8)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+0:hclIGVMOffset+4], 100) // DataSize
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+4:hclIGVMOffset+8], 1)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+8:hclIGVMOffset+12], 2) // SnpVmReport — not TDX
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+12:hclIGVMOffset+16], igvmHashTypeSHA256)
	provisionNVHCL(t, sim, envelope)

	_, err = readHCLEnvelope(sim)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ReportType")
}

func TestReadHCLEnvelope_IGVMUnsupportedHashType(t *testing.T) {
	t.Parallel()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sim.Close() })

	envelope := make([]byte, hclMinFullEnvelopeSize+8)
	binary.LittleEndian.PutUint32(envelope[0:4], hclMagicLE)
	binary.LittleEndian.PutUint32(envelope[4:8], hclVersionExpected)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+0:hclIGVMOffset+4], 100)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+4:hclIGVMOffset+8], 1)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+8:hclIGVMOffset+12], igvmReportTypeTDX)
	binary.LittleEndian.PutUint32(envelope[hclIGVMOffset+12:hclIGVMOffset+16], 2) // SHA384 — unsupported
	provisionNVHCL(t, sim, envelope)

	_, err = readHCLEnvelope(sim)
	require.Error(t, err)
	require.Contains(t, err.Error(), "HashType")
}

// =============================================================================
// extractV4ReportData direct unit
// =============================================================================

func TestExtractV4ReportData_TooShort(t *testing.T) {
	t.Parallel()
	_, err := extractV4ReportData(make([]byte, v4MinSize-1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestExtractV4ReportData_NotTDX(t *testing.T) {
	t.Parallel()
	v4 := make([]byte, v4MinSize)
	binary.LittleEndian.PutUint32(v4[v4OffTeeType:v4OffTeeType+4], 0x00000000) // SGX
	_, err := extractV4ReportData(v4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a TDX quote")
}

func TestExtractV4ReportData_HappyPath(t *testing.T) {
	t.Parallel()
	v4 := make([]byte, v4MinSize)
	binary.LittleEndian.PutUint32(v4[v4OffTeeType:v4OffTeeType+4], v4TeeTypeTDX)
	body := v4[v4HeaderSize:]
	want := bytes.Repeat([]byte{0x42}, reportDataSize)
	copy(body[v4BodyOffReport:], want)

	got, err := extractV4ReportData(v4)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// =============================================================================
// Helpers
// =============================================================================

// errIO returns an error usable with %w wrapping. Wraps stdlib
// errors.New so the returned value satisfies the "Is" / "Unwrap"
// machinery; we don't ship a custom error type for a single test
// helper.
func errIO(s string) error { return errors.New(s) }
