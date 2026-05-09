package paravisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// Paravisor-mediated TDX guest adapter (paravisor + IMDS-style QGS)
//
// This adapter targets confidential VM guests where a paravisor sits between
// the TDX module and the guest kernel: the paravisor owns the AK and locks
// V4.report_data at boot to a hash of an envelope it builds. The current
// production deployment uses the OpenHCL paravisor (Hyper-V isolation type 3,
// observed today on Azure CVM TDX), but the abstraction is the guest
// interface, not the cloud vendor — any future paravisor-style guest with
// the same wire-level shape (HCL envelope at NV 0x01400001 + IMDS-style QGS
// endpoint) reuses this code path.
//
// Production behavior:
//
//  1. /dev/tpmrm0 is the paravisor's vTPM. AK is pre-provisioned by
//     the paravisor at handle AKHandleParavisor (0x81000003) with
//     RSA-PSS-SHA256.
//  2. NV 0x01400001 holds an HCL envelope: 32B HCLA header, then a
//     1024B TDREPORT, then runtime claims we don't read in Path B. The
//     TDREPORT.report_data is locked by the paravisor at boot to
//     SHA256(AK_pub) — the load-bearing AK binding for the on-chain V4
//     verifier.
//  3. The IMDS quoting endpoint at http://169.254.169.254/acc/tdquote
//     accepts a base64-encoded TDREPORT and returns a base64-encoded V4
//     quote whose report_data matches the TDREPORT verbatim.
//  4. We then run TPM2_Quote(AK, pcrSel=empty, qualifyingData=user_data)
//     locally so the user_data is bound by the AK signature.
//
// Trust binding (verified by the on-chain hook): hash(bundle.AK_pub) ==
// V4.report_data[0:32]. Any mismatch — caller-tampered AK pub, paravisor
// bug, or QGS mis-routing — is rejected by the chain and locally by
// the kernel's self-check.
// =============================================================================

// VendorName is the stable identifier for this vendor.
const VendorName = "paravisor"

// envBundleMode is an operator-facing escape hatch. The paravisor path
// REFUSES STORY_TDX_BUNDLE_MODE=raw_v4 because V4.report_data is
// paravisor-locked to hash(VariableData) on paravisor-mediated guests —
// there is no way to bind user_data into V4.report_data. Refusing
// loudly here surfaces the misconfiguration instead of silently emitting
// a quote with meaningless binding semantics. (The direct vendor has no
// such env var: it always emits raw V4 with user_data in V4.report_data,
// the SGX-equivalent posture.)
const (
	envBundleMode   = "STORY_TDX_BUNDLE_MODE"
	bundleModeRawV4 = "raw_v4"
)

// HCL envelope NV index. Documented in az-tdx-vtpm and Microsoft's
// confidential-computing-cvm-guest-attestation reference repo.
//
// Exposed as a package-level variable rather than a const so tests can
// retarget to an owner-creatable range on the in-process simulator
// (the production index 0x01400001 is in the TCG-reserved platform-
// creator range, which the simulator refuses to NVDefineSpace under
// HandleOwner). Production code never reassigns this; the TPM2_NV_Read
// path is name-alg-agnostic so the read works regardless of which
// range the index physically lives in.
var hclNVIndex tpmutil.Handle = 0x01400001

// HCL envelope layout. The envelope is:
//
//	offset           size  field
//	0                32    ATTESTATION_HEADER (HCLA magic + version + ReportSize + ...)
//	32               1184  HW_ATTESTATION union
//	                       (SNP_VM_REPORT 1184 OR TDX_VM_REPORT 1024 + 160B padding)
//	1216             20    IGVM_REQUEST_DATA fixed prefix
//	                       (DataSize, Version, ReportType, ReportDataHashType, VariableDataSize)
//	1236             V     VariableData JSON envelope (HCLAkPub + HCLEkPub + vm-config + user-data)
//
// The `IGVM_REQUEST_DATA.VariableData` blob is what the paravisor
// hashes into TDREPORT.report_data: SHA256(VariableData) ==
// V4.report_data[:32]. See HclReportParser.cpp in Microsoft's
// confidential-computing-cvm-guest-attestation reference repo for the
// canonical reader.
const (
	hclHeaderSize          = 32
	tdReportSize           = 1024
	hclHWAttestationSize   = 1184 // SNP/TDX union; TDX is 1024 + 160 padding
	hclIGVMOffset          = hclHeaderSize + hclHWAttestationSize
	hclIGVMHeaderSize      = 20
	hclMinFullEnvelopeSize = hclIGVMOffset + hclIGVMHeaderSize
	hclEnvelopeMin         = hclHeaderSize + tdReportSize // legacy fast-path bound

	// HCLA magic — wire bytes [48 43 4C 41] in stream order, decoded as
	// little-endian uint32 = 0x414c4348. Asserted in the header check
	// so a misbehaving paravisor or a wrong NV index does not silently
	// produce garbage TDREPORT bytes that would otherwise pass through
	// to QGS and return an opaque error.
	hclMagicLE uint32 = 0x414c4348

	// HCL envelope version. Version 2 is current per the OpenHCL
	// paravisor reference. Future versions may extend the envelope; we
	// intentionally pin version=2 and reject anything else so a future
	// paravisor change forces a deliberate kernel update.
	hclVersionExpected uint32 = 2

	// IGVM ReportType for TDX. From HwVmReport.h IGVM_REPORT_TYPE enum.
	igvmReportTypeTDX uint32 = 4

	// IGVM ReportDataHashType. SHA256 = 1, SHA384 = 2, SHA512 = 3.
	igvmHashTypeSHA256 uint32 = 1
)

// IMDS QGS endpoint. The 169.254.169.254 IP is unrouted-link-local for
// the platform host; reaching it requires no host network configuration.
// The Path-B-relevant route is /acc/tdquote.
const (
	imdsTDQuoteURL  = "http://169.254.169.254/acc/tdquote"
	imdsHTTPTimeout = 30 * time.Second
)

// reportDataSize is the V4 report_data size (64 bytes). Mirrors the
// parent constant; defined here to keep the package import-cycle-free.
const reportDataSize = 64

// ErrNoParavisor is returned (wrapped) when this host does not appear
// to be a paravisor-mediated TDX guest. Probe failures wrap this
// sentinel so the parent's selectVendor uniformly detects "vendor not
// applicable" via errors.Is(err, ErrNoParavisor).
var ErrNoParavisor = errors.New("paravisor: host does not look like a paravisor-mediated TDX guest")

// ErrParavisorBundleModeRawV4 is returned when STORY_TDX_BUNDLE_MODE=raw_v4
// is set on a paravisor-mediated host. See vendor.GetQuote for the rationale.
var ErrParavisorBundleModeRawV4 = errors.New("paravisor: raw_v4 bundle mode is not supported (V4.report_data is paravisor-locked)")

// ErrParavisorAKBindingMismatch is returned by the QGS sanity check when
// the V4 we receive back does not have report_data == SHA256(AK_pub).
// This is defense in depth — the paravisor is supposed to enforce the
// binding at TDREPORT issuance — but we verify locally so a misbehaving
// QGS, a wrong AK handle, or a paravisor bug produces a loud error
// instead of a silently-broken bundle.
var ErrParavisorAKBindingMismatch = errors.New("paravisor: V4.report_data does not match SHA256(AK_pub) — AK binding broken")

// Vendor is the paravisor-mediated TDX adapter. Stateless after construction.
type Vendor struct{}

// Compile-time assertion against the platform.Vendor contract.
var _ platform.Vendor = (*Vendor)(nil)

// openTPM is the seam tests use to inject a simulator-backed TPM. The
// default opens /dev/tpmrm0 (the paravisor vTPM). Replacing this in
// tests must be guarded by t.Cleanup() to avoid leaking state across
// parallel runs.
var openTPM = func() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("paravisor: open /dev/tpmrm0: %w", err)
	}
	return rwc, nil
}

// imdsClient is the seam tests use to point HTTP traffic at an
// httptest.Server. Default is a fresh http.Client per call with a
// short timeout so the IMDS endpoint cannot wedge a goroutine
// indefinitely.
var imdsClient = func() *http.Client {
	return &http.Client{Timeout: imdsHTTPTimeout}
}

// imdsURL is overridable in tests.
var imdsURL = imdsTDQuoteURL

// Name returns VendorName.
func (Vendor) Name() string { return VendorName }

// Probe verifies the host looks like a paravisor-mediated TDX guest:
//  1. /dev/tpmrm0 exists and opens (or test seam returns OK).
//  2. NV 0x01400001 exists and decodes as an HCL envelope (HCLA magic +
//     version 2 + ≥1024B TDREPORT).
//  3. IMDS QGS endpoint is reachable (TCP connect; we don't POST a real
//     report on probe — that would consume one TDREPORT freshness slot
//     for no reason).
//
// All failures wrap ErrNoParavisor so the parent's selectVendor
// detects "no paravisor" uniformly. Probe is allowed to be expensive
// (one NV read + one HTTP HEAD) — we're not in a hot path, and the
// kernel calls Probe once per process.
func (Vendor) Probe() error {
	rwc, err := openTPM()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoParavisor, err)
	}
	defer rwc.Close()

	if err := probeNVHCL(rwc); err != nil {
		return fmt.Errorf("%w: %w", ErrNoParavisor, err)
	}
	if err := probeIMDSReachable(); err != nil {
		return fmt.Errorf("%w: %w", ErrNoParavisor, err)
	}
	return nil
}

// probeNVHCL reads the first hclEnvelopeMin bytes of NV 0x01400001
// and validates the HCLA header. Read is full-blob via NVReadEx;
// runtime claims tail is ignored.
func probeNVHCL(rwc io.ReadWriter) error {
	envelope, err := tpm2.NVReadEx(rwc, hclNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return fmt.Errorf("read NV 0x%08x: %w", uint32(hclNVIndex), err)
	}
	if len(envelope) < hclEnvelopeMin {
		return fmt.Errorf("HCL envelope too short: %d < %d", len(envelope), hclEnvelopeMin)
	}
	magic := binary.LittleEndian.Uint32(envelope[0:4])
	if magic != hclMagicLE {
		return fmt.Errorf("HCL header magic 0x%08x != expected 0x%08x", magic, hclMagicLE)
	}
	version := binary.LittleEndian.Uint32(envelope[4:8])
	if version != hclVersionExpected {
		return fmt.Errorf("HCL envelope version %d != expected %d", version, hclVersionExpected)
	}
	return nil
}

// probeIMDSReachable attempts a HEAD on the QGS endpoint to confirm
// the platform host is reachable. We avoid POSTing on probe so we do
// not consume a TDREPORT freshness slot for a binary "is it up"
// check. Any 4xx (e.g., 405 Method Not Allowed for HEAD) counts as
// reachable — the IMDS service is responding. Connection refused or
// timeout is "no paravisor / not reachable."
func probeIMDSReachable() error {
	req, err := http.NewRequest(http.MethodHead, imdsURL, nil)
	if err != nil {
		return fmt.Errorf("build HEAD request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := imdsClient().Do(req)
	if err != nil {
		return fmt.Errorf("IMDS HEAD failed: %w", err)
	}
	defer resp.Body.Close()
	// Any HTTP response counts as reachable.
	return nil
}

// QuoteProvider returns the paravisor-specific QuoteProvider. The
// paravisor adapter has no expensive per-construction setup (no AK
// creation — the paravisor owns the AK), so this is just a Vendor wrap.
func (Vendor) QuoteProvider() (platform.QuoteProvider, error) {
	if mode := os.Getenv(envBundleMode); mode == bundleModeRawV4 {
		return nil, fmt.Errorf("%w: STORY_TDX_BUNDLE_MODE=raw_v4 set", ErrParavisorBundleModeRawV4)
	}
	return &paravisorQuoteProvider{}, nil
}

// paravisorQuoteProvider is the production QuoteProvider for the
// paravisor adapter. It re-reads NV (and therefore TDREPORT) on every
// call so it never serves a stale TDREPORT from cache. The AK pub is
// read once on first call and cached; the paravisor never rotates it
// during a VM lifetime, and re-reading on every quote is wasted work.
//
// akMu serializes ensureAKPub so concurrent GetQuote callers cannot
// race on akPubDER assignment. The slice is never mutated after
// assignment (no append, full cap), so cached reads under akMu and
// later use without the lock are safe.
type paravisorQuoteProvider struct {
	akMu     sync.Mutex
	akPubDER []byte
}

// GetQuote produces a Path-B bundle for a paravisor-mediated TDX guest.
// See the package doc-comment for the step-by-step protocol. Refuses
// raw_v4 mode as a defense in depth (QuoteProvider also refuses at
// construction time; the env var is re-evaluated on every call so a
// runtime flip is honored, and a future caller that constructs
// paravisorQuoteProvider directly cannot bypass).
func (q *paravisorQuoteProvider) GetQuote(reportData []byte) ([]byte, error) {
	if mode := os.Getenv(envBundleMode); mode == bundleModeRawV4 {
		return nil, fmt.Errorf("%w: STORY_TDX_BUNDLE_MODE=raw_v4 set", ErrParavisorBundleModeRawV4)
	}
	if len(reportData) > reportDataSize {
		return nil, fmt.Errorf("paravisor: reportData length %d > %d", len(reportData), reportDataSize)
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("paravisor: open vTPM: %w", err)
	}
	defer rwc.Close()

	envelope, err := readHCLEnvelope(rwc)
	if err != nil {
		return nil, fmt.Errorf("paravisor: read HCL envelope: %w", err)
	}
	if len(envelope.VariableData) == 0 {
		return nil, fmt.Errorf("paravisor: HCL envelope missing IGVM_REQUEST_DATA.VariableData; "+
			"expected paravisor to embed AK-bound JSON envelope (envelope size=%d, full envelope expected)", len(envelope.TDReport))
	}

	v4, err := imdsTDQuote(envelope.TDReport)
	if err != nil {
		return nil, fmt.Errorf("paravisor: fetch V4 quote from QGS: %w", err)
	}

	akPubDER, err := q.ensureAKPub(rwc)
	if err != nil {
		return nil, fmt.Errorf("paravisor: read AK pub: %w", err)
	}

	// Verify the AK binding through VariableData. The paravisor sets
	// V4.report_data = SHA256(VariableData) at TDREPORT issuance and
	// QGS preserves it through to V4.report_data. We separately confirm
	// the AK pub the kernel uses for TPM2_Quote matches HCLAkPub.n
	// embedded in VariableData (otherwise an attacker could substitute
	// a forged AK and the on-chain check would still pass).
	if err := verifyParavisorAKBinding(v4, envelope.VariableData, akPubDER); err != nil {
		return nil, fmt.Errorf("paravisor: %w", err)
	}

	attest, sig, err := platform.TPMQuote(rwc, platform.AKHandleParavisor, reportData)
	if err != nil {
		return nil, fmt.Errorf("paravisor: TPM2_Quote: %w", err)
	}

	bundle, err := platform.MarshalBundle(v4, attest, sig, akPubDER, envelope.VariableData, platform.FlagTPMPresent, platform.VendorTagParavisor)
	if err != nil {
		return nil, fmt.Errorf("paravisor: marshal bundle: %w", err)
	}
	return bundle, nil
}

// ensureAKPub reads and caches the paravisor-provisioned AK pub at
// AKHandleParavisor. Subsequent calls hit the cache; we trust the
// paravisor to never rotate this AK during a VM lifetime, per the
// OpenHCL paravisor's documented behavior. Concurrent GetQuote callers
// are serialized through akMu on the cache miss path; the cache hit
// path is also under akMu but the critical section is a single pointer
// read, so contention is negligible.
func (q *paravisorQuoteProvider) ensureAKPub(rwc io.ReadWriter) ([]byte, error) {
	q.akMu.Lock()
	defer q.akMu.Unlock()

	if len(q.akPubDER) != 0 {
		return q.akPubDER, nil
	}
	der, err := platform.ReadAKPubDER(rwc, platform.AKHandleParavisor)
	if err != nil {
		return nil, err
	}
	q.akPubDER = der
	return der, nil
}

// hclEnvelope captures the parts of the NV 0x01400001 blob the kernel
// uses for Path-B bundle assembly: the embedded TDREPORT (sent to QGS)
// and the IGVM_REQUEST_DATA.VariableData JSON envelope (carried in the
// bundle so the on-chain verifier can recompute SHA256(variable_data)
// == V4.report_data[:32]).
type hclEnvelope struct {
	TDReport     []byte // 1024 bytes
	VariableData []byte // JSON; usually ~1.2 KB on paravisor-mediated guests
}

// readHCLEnvelope reads NV 0x01400001 and parses both the TDREPORT and
// the IGVM_REQUEST_DATA.VariableData blob. The legacy fast-path (TDREPORT
// only) is preserved when the envelope is too short to contain
// IGVM_REQUEST_DATA: that case is treated as a non-paravisor or
// pre-Path-B envelope and returns VariableData=nil. Production
// paravisor always emits the full envelope, so VariableData=nil there
// is a hard failure flagged by callers.
func readHCLEnvelope(rwc io.ReadWriter) (*hclEnvelope, error) {
	envelope, err := tpm2.NVReadEx(rwc, hclNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("NV read 0x%08x: %w", uint32(hclNVIndex), err)
	}
	if len(envelope) < hclEnvelopeMin {
		return nil, fmt.Errorf("HCL envelope too short: %d < %d", len(envelope), hclEnvelopeMin)
	}
	if magic := binary.LittleEndian.Uint32(envelope[0:4]); magic != hclMagicLE {
		return nil, fmt.Errorf("HCL header magic 0x%08x != expected 0x%08x", magic, hclMagicLE)
	}
	if version := binary.LittleEndian.Uint32(envelope[4:8]); version != hclVersionExpected {
		return nil, fmt.Errorf("HCL envelope version %d != expected %d", version, hclVersionExpected)
	}
	tdReport := envelope[hclHeaderSize : hclHeaderSize+tdReportSize]

	// IGVM_REQUEST_DATA fixed prefix begins at offset 1216 (after the
	// HW_ATTESTATION union). Tolerate a short envelope so older test
	// fixtures and pre-Path-B captures still parse the TDREPORT.
	if len(envelope) < hclMinFullEnvelopeSize {
		return &hclEnvelope{TDReport: tdReport}, nil
	}
	igvm := envelope[hclIGVMOffset:]
	dataSize := binary.LittleEndian.Uint32(igvm[0:4])
	igvmVersion := binary.LittleEndian.Uint32(igvm[4:8])
	reportType := binary.LittleEndian.Uint32(igvm[8:12])
	hashType := binary.LittleEndian.Uint32(igvm[12:16])
	varSize := binary.LittleEndian.Uint32(igvm[16:20])

	// All-zero IGVM area: a non-paravisor envelope or an SNP image where
	// the runtime data lives elsewhere. Return TDREPORT only; caller
	// decides whether VariableData is required.
	if dataSize == 0 && igvmVersion == 0 && reportType == 0 && varSize == 0 {
		return &hclEnvelope{TDReport: tdReport}, nil
	}

	if igvmVersion != 1 {
		return nil, fmt.Errorf("IGVM_REQUEST_DATA.Version=%d, expected 1", igvmVersion)
	}
	if reportType != igvmReportTypeTDX {
		return nil, fmt.Errorf("IGVM_REQUEST_DATA.ReportType=%d, expected %d (TdxVmReport)", reportType, igvmReportTypeTDX)
	}
	if hashType != igvmHashTypeSHA256 {
		return nil, fmt.Errorf("IGVM_REQUEST_DATA.HashType=%d, expected %d (SHA256)", hashType, igvmHashTypeSHA256)
	}
	varOff := hclIGVMOffset + hclIGVMHeaderSize
	if uint64(varOff)+uint64(varSize) > uint64(len(envelope)) {
		return nil, fmt.Errorf("IGVM_REQUEST_DATA.VariableDataSize=%d exceeds envelope (%d - %d = %d)",
			varSize, len(envelope), varOff, len(envelope)-varOff)
	}
	if varSize == 0 {
		// IGVM header populated but VariableData empty — invalid on a
		// paravisor-mediated guest because the paravisor must include
		// AK pub. Caller (verifyAKBinding) treats nil/empty as a hard
		// failure.
		return &hclEnvelope{TDReport: tdReport}, nil
	}
	variableData := envelope[varOff : varOff+int(varSize)]

	// Defensive: confirm SHA256(VariableData) == TDREPORT.report_data[:32]
	// before returning. The paravisor sets this binding at TDREPORT
	// issuance, so a mismatch indicates a corrupted envelope or a
	// non-paravisor image.
	want := sha256.Sum256(variableData)
	got := tdReport[128:160] // TDX_REPORTMAC.ReportData starts at byte 128
	if !bytes.Equal(got, want[:]) {
		return nil, fmt.Errorf("HCL envelope: SHA256(VariableData) != TDREPORT.report_data[:32]")
	}

	return &hclEnvelope{TDReport: tdReport, VariableData: variableData}, nil
}

// imdsTDQuoteRequest is the JSON body shape for the QGS POST. The
// reference paravisor sample (confidential-computing-cvm-guest-attestation)
// uses {"report":"<base64>"} as the request body.
type imdsTDQuoteRequest struct {
	Report string `json:"report"`
}

// imdsTDQuoteResponse is the JSON body shape the QGS endpoint returns.
// {"quote":"<base64 V4>"} per the reference sample.
type imdsTDQuoteResponse struct {
	Quote string `json:"quote"`
}

// imdsTDQuote POSTs the TDREPORT to the IMDS QGS endpoint and returns
// the V4 quote bytes. Any non-2xx response is wrapped with the body
// for operator diagnostics.
func imdsTDQuote(tdReport []byte) ([]byte, error) {
	body, err := json.Marshal(imdsTDQuoteRequest{Report: base64.StdEncoding.EncodeToString(tdReport)})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, imdsURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build POST request: %w", err)
	}
	req.Header.Set("Metadata", "true")
	req.Header.Set("Content-Type", "application/json")

	resp, err := imdsClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("IMDS returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed imdsTDQuoteResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode response JSON: %w", err)
	}
	v4, err := decodeQuoteBase64(parsed.Quote)
	if err != nil {
		return nil, fmt.Errorf("decode quote base64: %w", err)
	}
	if len(v4) == 0 {
		return nil, fmt.Errorf("IMDS returned empty quote")
	}
	return v4, nil
}

// decodeQuoteBase64 decodes the QGS response Quote field. The live
// /acc/tdquote endpoint observed today returns URL-safe base64 without
// padding (RawURLEncoding) — verified empirically against the live IMDS
// endpoint on production paravisor-mediated TDX SKUs. We try the
// encodings in the order most likely to match, returning the first
// successful decode. Standard encodings are included as forward-compat
// seam; some pre-release SKUs were observed returning standard alphabet,
// and an explicit fallback avoids a hard regression if the format ever
// changes back.
func decodeQuoteBase64(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if v, err := enc.DecodeString(s); err == nil {
			return v, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

// verifyParavisorAKBinding asserts the two-step paravisor binding:
//
//  1. SHA256(VariableData) == V4.report_data[:32].
//     The paravisor sets this at TDREPORT issuance; QGS preserves it
//     through to V4.report_data. A mismatch indicates a corrupted
//     envelope, the QGS routed elsewhere, or a misbehaving paravisor.
//
//  2. The AK pub the kernel uses for TPM2_Quote matches the HCLAkPub
//     entry inside VariableData (compared by RSA modulus). Without
//     this, an attacker could substitute their own AK pub in the
//     bundle: chain step (1) would still pass (we hash VariableData,
//     not AKPub), and the TPM2 sig would verify under the substitute
//     key. The HCLAkPub entry IS what the paravisor provisioned and
//     hashed; binding bundle.AKPub to it closes the gap.
//
// Together these ground the AK in the TDX TCB through the paravisor.
func verifyParavisorAKBinding(v4 []byte, variableData []byte, akPubDER []byte) error {
	v4ReportData, err := extractV4ReportData(v4)
	if err != nil {
		return fmt.Errorf("extract V4 report_data: %w", err)
	}
	want := sha256.Sum256(variableData)
	if !bytes.Equal(v4ReportData[:32], want[:]) {
		return fmt.Errorf("%w: SHA256(VariableData) != V4.report_data[:32]", ErrParavisorAKBindingMismatch)
	}
	// Trailing 32 bytes of V4.report_data are zero on paravisor-mediated
	// guests (the JSON hash is 32 bytes; paravisor zero-pads to 64).
	for i := 32; i < 64; i++ {
		if v4ReportData[i] != 0 {
			return fmt.Errorf("%w: report_data byte %d non-zero (got 0x%02x)",
				ErrParavisorAKBindingMismatch, i, v4ReportData[i])
		}
	}

	// Confirm AK pub matches HCLAkPub embedded in VariableData JSON.
	// Comparing RSA modulus is sufficient; the paravisor template fixes
	// the exponent to 65537 and the algorithm to RSA-2048.
	hclModulus, err := platform.ExtractHCLAkPubModulus(variableData)
	if err != nil {
		return fmt.Errorf("%w: extract HCLAkPub: %w", ErrParavisorAKBindingMismatch, err)
	}
	akModulus, err := platform.ExtractRSAModulusFromDER(akPubDER)
	if err != nil {
		return fmt.Errorf("%w: extract AK modulus: %w", ErrParavisorAKBindingMismatch, err)
	}
	if !bytes.Equal(hclModulus, akModulus) {
		return fmt.Errorf("%w: HCLAkPub.n != bundle.AKPub modulus", ErrParavisorAKBindingMismatch)
	}
	return nil
}

// extractV4ReportData walks the V4 quote header + body to retrieve
// the 64-byte report_data field. We hand-roll the byte offsets here
// rather than importing enclave/tdx (which would create an import
// cycle: tdx -> platform/paravisor -> tdx). The offsets mirror the
// enclave/tdx parser.
//
// V4 layout (relative to start of quote):
//
//	header: 48 bytes; tee_type at offset 4 (LE uint32) must be 0x81 for TDX.
//	body:   starts at offset 48; report_data at body offset 520; size 64.
const (
	v4HeaderSize           = 48
	v4OffTeeType           = 4
	v4TeeTypeTDX    uint32 = 0x00000081
	v4BodyOffReport        = 520
	v4MinSize              = v4HeaderSize + v4BodyOffReport + reportDataSize // 632
)

func extractV4ReportData(v4 []byte) ([]byte, error) {
	if len(v4) < v4MinSize {
		return nil, fmt.Errorf("V4 quote too short: %d < %d", len(v4), v4MinSize)
	}
	teeType := binary.LittleEndian.Uint32(v4[v4OffTeeType : v4OffTeeType+4])
	if teeType != v4TeeTypeTDX {
		return nil, fmt.Errorf("not a TDX quote: tee_type=0x%08x", teeType)
	}
	body := v4[v4HeaderSize:]
	return body[v4BodyOffReport : v4BodyOffReport+reportDataSize], nil
}

// init registers the paravisor adapter with the platform registry.
// Registered AFTER direct (per backend.go's blank-import order) so the
// auto-detect loop tries direct first; on paravisor-mediated TDX guests,
// direct probe fails (configfs-tsm rejected by the paravisor) and the
// paravisor probe succeeds.
func init() {
	platform.Register(Vendor{})
	log.Debugf("paravisor: TDX vendor registered")
}
