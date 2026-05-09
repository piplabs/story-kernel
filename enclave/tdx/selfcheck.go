package tdx

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// =============================================================================
// Startup self-check.
//
// Run once at backend init() *after* the TPM and quote provider are open.
// Sequence:
//
//   1. TPM responsive — TPM2_GetCapability succeeds.
//   2. PCRs non-zero — every PCR referenced by any provider has been
//      extended; an all-zero PCR indicates the boot chain failed to feed
//      the vTPM and the trust assumption is broken.
//   3. Provider digest match — for each provider with non-nil
//      ExpectedDigest, compute the current PolicyPCR digest and compare.
//      If at least one provider is populated, at least one must match;
//      otherwise fail-closed. If ALL providers have ExpectedDigest=nil,
//      this is bootstrap mode: WARN log + proceed.
//   4. Self-quote — generate a TDX quote with []byte{0} reportData and
//      assert MRTD non-zero.
//
// Bootstrap WARN log format must include the empirically measured digest
// in copy-pasteable hex so operators can update supportedProviders source.
// =============================================================================

// runSelfCheck is invoked by tdxBackend.init after the TPM and quote
// provider are open. It returns an error on any verification failure; the
// caller (init) wraps the error in log.Fatal so the process exits non-zero.
func (b *Backend) runSelfCheck() error {
	// Step 1: TPM responsive.
	if _, _, err := tpm2.GetCapability(b.tpm, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.Manufacturer)); err != nil {
		return fmt.Errorf("self-check: TPM2_GetCapability failed: %w", err)
	}

	// Step 2: Read every PCR referenced by any provider; assert all non-zero.
	pcrSet := uniqueSorted(allProviderPCRs(b.providers))
	if len(pcrSet) == 0 {
		return fmt.Errorf("self-check: no PCRs configured by any provider")
	}
	hashAlg := b.providers[0].Hash
	pcrValues, err := readPCRs(b.tpm, tpm2.PCRSelection{Hash: hashAlg, PCRs: pcrSet})
	if err != nil {
		return fmt.Errorf("self-check: read PCRs %v: %w", pcrSet, err)
	}
	for _, idx := range pcrSet {
		v, ok := pcrValues[idx]
		if !ok || isZero(v) {
			return fmt.Errorf("self-check: PCR%d is zero or missing — vTPM not measured", idx)
		}
	}

	// Step 3: For each provider with non-nil ExpectedDigest, compute the
	// current PolicyPCR digest over its PCRs and compare. Track matches.
	populated := 0
	matched := 0
	currentDigests := make([]string, 0, len(b.providers))
	for _, p := range b.providers {
		cur := computePCRDigest(p.PCRSelection, pcrValues)
		currentDigests = append(currentDigests, hex.EncodeToString(cur))
		if p.ExpectedDigest == nil {
			continue
		}
		populated++
		if bytes.Equal(cur, p.ExpectedDigest) {
			matched++
		}
	}

	switch {
	case populated == 0:
		// Bootstrap mode.
		log.Warnf(
			"TDX backend in bootstrap mode — no provider has a populated ExpectedDigest.\n"+
				"       Current PCR digests by provider:\n%s\n"+
				"       Populate the matching entry in supportedProviders[].ExpectedDigest\n"+
				"       and rebuild before production deployment.",
			formatBootstrapDigests(b.providers, currentDigests),
		)
	case matched == 0:
		// Fail-closed: providers configured but none match.
		return fmt.Errorf(
			"self-check: no supported provider matches current PCR state. "+
				"current digests: %s — refuse to start",
			strings.Join(currentDigests, ", "),
		)
	default:
		log.Infof("TDX backend self-check: %d/%d provider(s) match current PCR state", matched, populated)
	}

	// Step 4: Self-quote with a known canary so the bundle path can
	// validate qualifyingData round-trips through TPM2_Quote. The
	// canary is short and printable for log-friendliness; on a
	// paravisor-mediated guest it is signed by the paravisor AK, on
	// direct it is signed by our kernel-provisioned AK.
	canary := []byte("tdx-self-check-canary")
	quote, err := b.quoteProvider.GetQuote(canary)
	if err != nil {
		return fmt.Errorf("self-check: self-quote failed: %w", err)
	}

	// Bundle-mode vendors (paravisor) return STBN-prefixed bytes; raw-V4
	// vendors (direct) return V4 directly. Detect by magic and dispatch.
	//
	// On the raw-V4 path, the direct vendor has no AK and no
	// TPM2_Quote — qualifyingData round-trip is intentionally absent
	// here because the direct vendor binds user_data via the SGX-
	// equivalent V4.report_data slot instead. Verifying that the
	// canary we passed in lands in V4.report_data exercises the same
	// end-to-end binding the on-chain TDX validation hook checks
	// against keccak256(EnclaveInstanceData).
	if platform.HasBundleMagic(quote) {
		if err := b.verifySelfBundle(quote, canary); err != nil {
			return fmt.Errorf("self-check: bundle verify failed: %w", err)
		}
	} else {
		parsed, err := parseTDXQuote(quote)
		if err != nil {
			return fmt.Errorf("self-check: parse self-quote: %w", err)
		}
		if isZero(parsed.MRTD) {
			return fmt.Errorf("self-check: MRTD is zero — TD measurement broken")
		}
		// V4.report_data must carry the canary verbatim in its leading
		// bytes (the rest is zero-padded by the vendor). This is the
		// only kernel-side check the raw-V4 path admits because there
		// is no AK signature to round-trip through. On the bundle path
		// the canary lives in TPMS_ATTEST.qualifyingData and is
		// verified by verifySelfBundle.
		if !bytes.Equal(parsed.ReportData[:len(canary)], canary) {
			return fmt.Errorf("self-check: V4.report_data leading bytes %x != canary %x — direct vendor binding broken",
				parsed.ReportData[:len(canary)], canary)
		}
	}

	return nil
}

// verifySelfBundle runs the full Path-B verification ladder over a self-
// produced bundle. This is the kernel-side mirror of the on-chain
// verifier; if on-chain verification fails on a bundle the kernel
// produced but verifySelfBundle passed, the bug is on chain. Symmetry
// is the point.
//
// Steps (in order, fail-closed at each):
//
//  1. Magic == STBN (HasBundleMagic, already checked by caller).
//  2. UnmarshalBundle succeeds.
//  3. parseTDXQuote(bundle.TdxV4) succeeds.
//  4. AK binding (vendor-aware):
//     - Direct (RuntimeData empty): SHA256(bundle.AKPub) ==
//     V4.report_data[0:32]. Bytes 32..63 MUST be zero.
//     - Paravisor-mediated (RuntimeData = paravisor JSON envelope):
//     SHA256(bundle.RuntimeData) == V4.report_data[0:32], AND
//     JWK("HCLAkPub").n modulus == bundle.AKPub modulus. Bytes
//     32..63 of report_data MUST be zero.
//  5. PSS-verify bundle.TpmSig over bundle.TpmAttest with bundle.AKPub.
//  6. Decode TPMS_ATTEST: magic == TPM_GENERATED_VALUE, type ==
//     TPM_ST_ATTEST_QUOTE, ExtraData (qualifyingData) == canary.
//  7. MRTD non-zero (existing assertion).
func (b *Backend) verifySelfBundle(bundleBytes []byte, canary []byte) error {
	bundle, err := platform.UnmarshalBundle(bundleBytes)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if !bundle.HasTPM() {
		return fmt.Errorf("bundle missing TPM_PRESENT — verifier requires TPM2 evidence")
	}

	parsed, err := parseTDXQuote(bundle.TdxV4)
	if err != nil {
		return fmt.Errorf("parse V4: %w", err)
	}

	// Step 4: vendor-aware AK binding.
	if err := verifyBundleAKBinding(bundle, parsed); err != nil {
		return err
	}
	for i := 32; i < 64; i++ {
		if parsed.ReportData[i] != 0 {
			return fmt.Errorf("V4.report_data[%d]=0x%02x, must be zero (reserved)",
				i, parsed.ReportData[i])
		}
	}

	// Step 5: PSS-verify TPMS_ATTEST signature with AK pub. The TPM
	// signs the SHA-256 hash of the attestation bytes; salt length
	// matches the digest.
	pkAny, err := x509.ParsePKIXPublicKey(bundle.AKPub)
	if err != nil {
		return fmt.Errorf("parse AK SPKI: %w", err)
	}
	rsaPub, ok := pkAny.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("AK pub is %T, expected *rsa.PublicKey", pkAny)
	}
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(bundle.TpmSig))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if sig.Alg != platform.ExpectedSigAlg {
		return fmt.Errorf("AK sig alg 0x%04x != expected 0x%04x", uint16(sig.Alg), uint16(platform.ExpectedSigAlg))
	}
	if sig.RSA == nil || sig.RSA.HashAlg != platform.ExpectedHashAlg {
		return fmt.Errorf("AK sig hash alg != SHA-256")
	}
	digest := sha256.Sum256(bundle.TpmAttest)
	// RSASSA == PKCS#1 v1.5. The OpenHCL paravisor uses this scheme;
	// direct vendor mirrors it for cross-vendor uniformity.
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig.RSA.Signature); err != nil {
		return fmt.Errorf("RSASSA verify: %w", err)
	}

	// Step 6: Decode TPMS_ATTEST and assert qualifying data + magic +
	// type. AttestationData.Magic is enforced by go-tpm at decode.
	attestData, err := tpm2.DecodeAttestationData(bundle.TpmAttest)
	if err != nil {
		return fmt.Errorf("decode TPMS_ATTEST: %w", err)
	}
	if attestData.Type != tpm2.TagAttestQuote {
		return fmt.Errorf("TPMS_ATTEST.type 0x%04x != TPM_ST_ATTEST_QUOTE", uint16(attestData.Type))
	}
	if !bytes.Equal(attestData.ExtraData, tpmutil.U16Bytes(canary)) {
		return fmt.Errorf("TPMS_ATTEST.qualifyingData %x != canary %x",
			attestData.ExtraData, canary)
	}

	// Step 7: MRTD non-zero — existing invariant from the legacy path.
	if isZero(parsed.MRTD) {
		return fmt.Errorf("MRTD is zero — TD measurement broken")
	}
	return nil
}

// verifyBundleAKBinding runs the vendor-specific AK-to-V4 binding
// check. Direct vendor (and any bundle without runtime_data) hashes
// the AK pub DER directly. The paravisor vendor hashes the
// paravisor-emitted VariableData JSON envelope, then proves the AK pub
// in the bundle matches the modulus inside that JSON. The two paths
// are cryptographically distinct but share the same end-property:
// V4.report_data binds the AK that signed bundle.TpmAttest.
func verifyBundleAKBinding(bundle *platform.Bundle, parsed *parsedTDXQuote) error {
	if len(bundle.RuntimeData) == 0 {
		// Direct path. SHA256(bundle.AKPub) == V4.report_data[0:32].
		akHash := sha256.Sum256(bundle.AKPub)
		if !bytes.Equal(parsed.ReportData[:32], akHash[:]) {
			return fmt.Errorf("AK binding mismatch: V4.report_data[0:32]=%x sha256(ak)=%x",
				parsed.ReportData[:32], akHash[:])
		}
		return nil
	}
	// Paravisor / runtime-data path. SHA256(bundle.RuntimeData) ==
	// V4.report_data[0:32]. Then bundle.AKPub modulus == HCLAkPub.n
	// inside RuntimeData.
	rtHash := sha256.Sum256(bundle.RuntimeData)
	if !bytes.Equal(parsed.ReportData[:32], rtHash[:]) {
		return fmt.Errorf("AK binding mismatch: V4.report_data[0:32]=%x sha256(runtime_data)=%x",
			parsed.ReportData[:32], rtHash[:])
	}
	hclModulus, err := platform.ExtractHCLAkPubModulus(bundle.RuntimeData)
	if err != nil {
		return fmt.Errorf("AK binding: extract HCLAkPub: %w", err)
	}
	akModulus, err := platform.ExtractRSAModulusFromDER(bundle.AKPub)
	if err != nil {
		return fmt.Errorf("AK binding: extract AK modulus: %w", err)
	}
	if !bytes.Equal(hclModulus, akModulus) {
		return fmt.Errorf("AK binding mismatch: HCLAkPub.n != bundle.AKPub modulus")
	}
	return nil
}

// allProviderPCRs returns the union of all PCR indexes across providers.
func allProviderPCRs(providers []ProviderPolicy) []int {
	var out []int
	for _, p := range providers {
		out = append(out, p.PCRs...)
	}
	return out
}

// uniqueSorted returns a sorted copy of the input with duplicates removed.
func uniqueSorted(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	cp := append([]int(nil), in...)
	sort.Ints(cp)
	out := cp[:1]
	for _, v := range cp[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// formatBootstrapDigests returns indented "name (PCRs ...): 0x<hex>" lines
// for the WARN log. One line per provider, in supportedProviders order.
func formatBootstrapDigests(providers []ProviderPolicy, digests []string) string {
	var sb strings.Builder
	for i, p := range providers {
		fmt.Fprintf(&sb, "         %s (PCRs %s): 0x%s\n", p.Name, joinInts(p.PCRs), digests[i])
	}
	out := sb.String()
	// Trim trailing newline so the WARN message doesn't include a dangling
	// blank line before the next "Populate the matching entry..." line.
	out = strings.TrimRight(out, "\n")
	return out
}

// joinInts is fmt-helper to print PCR index lists as "7,11".
func joinInts(s []int) string {
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}
