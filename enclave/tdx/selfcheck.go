package tdx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	log "github.com/sirupsen/logrus"
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
//   4. Self-quote — generate a TDX quote with a canary reportData and
//      assert MRTD non-zero and the canary round-trips into
//      V4.report_data.
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
	pcrValues, err := readPCRs(b.tpm, tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: pcrSet})
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

	// Step 4: Self-quote with a known canary and verify it round-trips
	// into V4.report_data. The direct vendor binds user_data via the
	// SGX-equivalent V4.report_data slot, so we just check the canary
	// lands in the leading bytes and MRTD is non-zero — the same
	// end-to-end binding the on-chain TDX validation hook checks
	// against keccak256(EnclaveInstanceData).
	canary := []byte("tdx-self-check-canary")
	quote, err := b.quoteProvider.GetQuote(canary)
	if err != nil {
		return fmt.Errorf("self-check: self-quote failed: %w", err)
	}

	parsed, err := parseTDXQuote(quote)
	if err != nil {
		return fmt.Errorf("self-check: parse self-quote: %w", err)
	}
	if isZero(parsed.MRTD) {
		return fmt.Errorf("self-check: MRTD is zero — TD measurement broken")
	}
	if !bytes.Equal(parsed.ReportData[:len(canary)], canary) {
		return fmt.Errorf("self-check: V4.report_data leading bytes %x != canary %x — direct vendor binding broken",
			parsed.ReportData[:len(canary)], canary)
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
