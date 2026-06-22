package tdx

import (
	"github.com/google/go-tpm/legacy/tpm2"
)

// pcrPolicyHash is the single hash bank used by the entire PCR sealing policy:
// every supportedProviders entry, the PCR 12 self-extend (extendPCR12Once),
// the PolicyPCR/PolicyOR trial sessions, and computePCRDigest all use it.
// SHA-256 is fixed system-wide — it is NOT a per-provider choice, so callers
// reference this constant rather than deriving it from providers[0].Hash.
//
// Note: this is distinct from RTMR3, which is SHA-384 per the TDX architecture
// (see hashSelfBinary / extendBinaryMeasurementOnce). Do not conflate them.
const pcrPolicyHash = tpm2.AlgSHA256

// ProviderPolicy describes one acceptable PCR-extension state under which
// sealed data may be unsealed. A multi-provider deployment lists every state
// it accepts; PolicyOR(branches...) at the TPM combines them into a single
// auth policy bound to the sealed object.
//
// Source-of-truth is the supportedProviders Go slice below. Adding a
// provider is a code edit + redeploy; there is no on-disk configuration and
// no operator-injected state for sealing policy. ExpectedDigest may be nil
// at first deployment ("bootstrap mode"): the startup self-check emits the
// empirically measured digest as a WARN log so the operator can paste it
// back into source before the next build.
type ProviderPolicy struct {
	// Name is a short stable identifier for logs and metrics.
	Name string

	// PCRSelection bundles the PCR list and digest algorithm. It is the
	// upstream go-tpm type so it can be passed directly to tpm2.PolicyPCR
	// and computePolicyDigest. Embedding promotes its fields (PCRs, Hash)
	// onto ProviderPolicy itself for caller ergonomics.
	tpm2.PCRSelection

	// ExpectedDigest is the digest that the TPM's PolicyPCR command must
	// compute against the listed PCRs. If nil, this entry is in bootstrap
	// mode and is excluded from PolicyOR construction (a sealed blob created
	// in bootstrap mode is bound to the *current* empirical digest captured
	// at first seal, not to a code-shipped digest).
	ExpectedDigest []byte
}

// supportedProviders defines the PolicyOR branches used for sealing.
//
// IMPORTANT: PolicyOR digest computation is order-sensitive. Reordering or
// removing entries invalidates ALL existing sealed blobs that were written
// against the prior order; affected operators must re-seal. New entries
// appended at the end are forward-compatible (existing blobs continue to
// unseal as long as their original entries remain present in the same order).
//
// supportedProviders is the canonical list of PCR-extension states under
// which we will agree to unseal data. ANY change requires a code edit and a
// rebuild + redeploy.
//
// PCR choice rationale:
//   - PCR 7  — Secure Boot policy. Conventionally bound to the firmware /
//     bootloader signature chain. Captures shim/grub measurements when
//     Secure Boot is enabled in the TD.
//   - PCR 11 — Linux IMA / dm-verity / disk-image root-hash measurements.
//     This is where the operator-built TD initrd extends its
//     identity-of-payload measurement during boot.
//   - PCR 12 — story-kernel ELF binary measurement. The initrd extends
//     PCR 12 with SHA-256 of /opt/story-kernel/bin/story-kernel before
//     exec'ing the kernel. The measurer (initrd) is pinned by the platform
//     commitment (RTMR1/RTMR2), and PCR is append-only, so a userspace
//     kernel cannot forge this value at runtime — binding sealing to the
//     running ELF the way SGX EGETKEY binds it to MRENCLAVE. Operators
//     MUST extend PCR 12 from initrd; if it stays zero, runSelfCheck fails
//     closed.
var supportedProviders = []ProviderPolicy{
	{
		Name: "default-tpm-pcrs-7-11-12",
		PCRSelection: tpm2.PCRSelection{
			Hash: pcrPolicyHash,
			PCRs: []int{7, 11, 12},
		},
		ExpectedDigest: nil, // populated empirically on first deployment
	},
}
