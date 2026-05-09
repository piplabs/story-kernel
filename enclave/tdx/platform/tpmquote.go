package platform

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// =============================================================================
// Shared TPM2_Quote helper
//
// Used by the paravisor vendor. (The direct vendor returns raw V4 quotes
// with the caller's user_data padded into V4.report_data, mirroring the
// SGX backend's report_data semantics; it does not call this helper.)
// The helper drives TPM2_Quote with an empty PCR selection so the TPM
// only signs the caller-supplied qualifyingData; PCR-based attestation
// is orthogonal and already handled by the sealing policy in seal.go.
//
// Returned values:
//   - attest: the TPMS_ATTEST blob the TPM constructs and signs. The
//     TPM2B_ATTEST 16-bit size prefix is stripped — DecodeAttestationData /
//     the on-chain verifier expects the bare structure.
//   - sigBlob: the TPMT_SIGNATURE blob the TPM emits. We re-encode via
//     tpm2.Signature.Encode so the on-chain side can DecodeSignature in
//     one step. For RSA-PSS the sig is fixed-length (256 bytes for
//     RSA-2048) and ECDSA is two big-endian integers; both round-trip
//     losslessly.
//
// Hard requirements:
//   - The AK at akHandle MUST produce RSA-2048 PKCS#1 v1.5 (RSASSA)
//     signatures over SHA-256. This matches what the OpenHCL paravisor
//     pre-provisions at AKHandleParavisor on paravisor-mediated TDX
//     guests (verified empirically on weu-dkg-tdx-test-tdx1:
//     `tpm2_readpublic -c 0x81000003` → scheme=rsassa, hash=sha256).
//   - qualifyingData is bounded by the TPM's TPM2B_DATA hard limit
//     (typ. 64 bytes; 128 in some implementations). We cap at 64 to
//     match the conservative interpretation; oversized inputs are
//     rejected here.
// =============================================================================

// tpmQualifyingDataMax is the conservative upper bound for the
// qualifyingData parameter to TPM2_Quote. The TPM 2.0 Library spec leaves
// the size implementation-defined; reference TPM2 implementations
// (libtpms, swtpm, OpenHCL paravisor vTPM) all enforce 64 bytes.
// Going over this limit on real hardware returns TPM_RC_SIZE; we mirror
// that here so kernel-side bugs surface deterministically without a TPM
// round-trip.
const tpmQualifyingDataMax = 64

// ExpectedSigAlg / ExpectedHashAlg are the kernel-side expectations
// for the TPMT_SIGNATURE the TPM emits over a TPM2_Quote. They must
// match the on-chain verifier's hard-coded values exactly. Changing
// them is a breaking format change that requires a bundle-version
// bump (see bundle.go's BundleVersion). Exported so selfcheck.go can
// pin verification to the same constants.
const (
	ExpectedSigAlg  = tpm2.AlgRSASSA
	ExpectedHashAlg = tpm2.AlgSHA256
)

// AKHandleParavisor is the well-known persistent handle the OpenHCL
// paravisor pre-provisions on a paravisor-mediated TDX guest. We never
// create this key — the paravisor owns it, and its public is already
// bound to TDREPORT.report_data at boot. Mismatching this handle means
// we'd read a key the paravisor did not bind, breaking the load-bearing
// AK trust chain (V4.report_data == hash(AK_pub)).
const AKHandleParavisor tpmutil.Handle = 0x81000003

// AKTemplate is the RSA-2048-RSASSA-SHA256 AK template that matches the
// OpenHCL paravisor's pre-provisioned AK (verified empirically:
// `tpm2_readpublic -c 0x81000003` shows scheme=rsassa, hash=sha256), so
// the on-chain verifier has a single verify path regardless of vendor.
// Restricted | Sign attributes are required for TPM2_Quote.
//
// The direct vendor never provisions an AK — it returns raw V4 quotes
// with the caller's user_data padded into V4.report_data, mirroring the
// SGX backend's report_data semantics. Only the paravisor vendor consumes
// this template (indirectly, via the paravisor itself).
//
// Notes:
//   - FlagSignerDefault expands to Sign | Restricted | FixedTPM |
//     FixedParent | SensitiveDataOrigin | UserWithAuth — every flag
//     TPM2_Quote requires for an AK plus standard non-migratability.
//   - KeyBits=2048. ECC ECDSA-P256 is intentionally not supported;
//     per design §4 RSA-2048 is the chosen uniform algorithm. EIP-7212
//     P-256 precompile adoption may revisit this later.
//   - PKCS#1 v1.5 is older than PSS but is what the OpenHCL paravisor
//     emits. The chain accepts both byte-stable wire formats; we pin
//     PKCS#1 v1.5 here for vendor uniformity.
func AKTemplate() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

// ReadAKPubDER reads the persistent AK at the given handle and returns
// its public area encoded as a DER SubjectPublicKeyInfo. SPKI is the
// canonical wire format for the bundle's ak_pub field (per design §3.3).
//
// Fails closed:
//   - If the handle is empty or the public area is not RSA, returns an
//     explicit error rather than projecting a partial key.
//   - If the modulus length is not 2048 bits (256 bytes), rejects.
//     RSA-2048 is the only AK modulus length the on-chain verifier
//     accepts in BundleVersion=1.
func ReadAKPubDER(rwc io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	pub, _, _, err := tpm2.ReadPublic(rwc, handle)
	if err != nil {
		return nil, fmt.Errorf("tdx: TPM2_ReadPublic(0x%08x): %w", uint32(handle), err)
	}
	if pub.Type != tpm2.AlgRSA {
		return nil, fmt.Errorf("tdx: AK at 0x%08x is not RSA (alg=0x%04x)", uint32(handle), uint16(pub.Type))
	}
	if pub.RSAParameters == nil {
		return nil, fmt.Errorf("tdx: AK at 0x%08x missing RSAParameters", uint32(handle))
	}
	if pub.RSAParameters.KeyBits != 2048 {
		return nil, fmt.Errorf("tdx: AK at 0x%08x has %d-bit modulus, expect 2048", uint32(handle), pub.RSAParameters.KeyBits)
	}
	pk, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("tdx: extract AK public key: %w", err)
	}
	rsaPub, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("tdx: AK public is %T, expected *rsa.PublicKey", pk)
	}
	der, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		return nil, fmt.Errorf("tdx: encode AK pub as SPKI: %w", err)
	}
	return der, nil
}

// TPMQuote runs TPM2_Quote(handle=akHandle, pcrSel=empty,
// qualifyingData=qualifyingData) and returns the marshaled
// TPMS_ATTEST + TPMT_SIGNATURE pair for embedding in a Path-B bundle.
//
// Empty PCR selection is intentional (design §3.4): we use the AK only
// to sign caller-supplied qualifyingData. PCR binding is handled by the
// sealing policy in seal.go and is out of scope for the user_data
// channel.
//
// Validation gates (defense in depth — the on-chain verifier enforces
// the same constraints):
//   - qualifyingData length capped at tpmQualifyingDataMax.
//   - sigAlg must be ExpectedSigAlg (RSASSA = PKCS#1 v1.5) and hashAlg
//     must be ExpectedHashAlg (SHA-256). A misconfigured AK template
//     would let the TPM emit an RSA-PSS signature; we reject that
//     here so the kernel cannot ship bundles the chain will refuse.
func TPMQuote(rwc io.ReadWriter, akHandle tpmutil.Handle, qualifyingData []byte) (attest []byte, sigBlob []byte, err error) {
	if len(qualifyingData) > tpmQualifyingDataMax {
		return nil, nil, fmt.Errorf("tdx: qualifyingData length %d > %d", len(qualifyingData), tpmQualifyingDataMax)
	}

	emptySel := tpm2.PCRSelection{Hash: ExpectedHashAlg, PCRs: nil}
	// sigAlg=AlgNull tells the TPM to use the AK template's default
	// signing scheme (RSASSA-SHA256 for our template). The same call
	// works on a paravisor-mediated guest where the
	// paravisor-provisioned AK is also RSASSA.
	attest, sigRaw, err := tpm2.QuoteRaw(rwc, akHandle, "", "", qualifyingData, emptySel, tpm2.AlgNull)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx: TPM2_Quote(0x%08x): %w", uint32(akHandle), err)
	}

	// Decode + re-encode the signature to:
	//   (a) validate the algorithm is RSASSA-SHA256 as expected,
	//   (b) produce a stable wire form (algId|hashAlg|len|sig) for the
	//       on-chain verifier.
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(sigRaw))
	if err != nil {
		return nil, nil, fmt.Errorf("tdx: decode TPMT_SIGNATURE: %w", err)
	}
	if sig.Alg != ExpectedSigAlg {
		return nil, nil, fmt.Errorf("tdx: AK signature algorithm 0x%04x != expected 0x%04x (RSASSA)", uint16(sig.Alg), uint16(ExpectedSigAlg))
	}
	if sig.RSA == nil {
		return nil, nil, fmt.Errorf("tdx: TPMT_SIGNATURE has nil RSA payload")
	}
	if sig.RSA.HashAlg != ExpectedHashAlg {
		return nil, nil, fmt.Errorf("tdx: AK hash algorithm 0x%04x != expected 0x%04x (SHA-256)", uint16(sig.RSA.HashAlg), uint16(ExpectedHashAlg))
	}
	encoded, err := sig.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("tdx: re-encode TPMT_SIGNATURE: %w", err)
	}
	return attest, encoded, nil
}
