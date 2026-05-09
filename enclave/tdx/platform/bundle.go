package platform

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// =============================================================================
// Path-B "STBN" quote bundle format.
//
// The bundle composes a TDX V4 quote with a TPM2_Quote signed by an
// Attestation Key (AK), so that callers can bind arbitrary user_data even on
// vendors where V4.report_data is not under guest control (notably
// paravisor-mediated guests, where the paravisor locks report_data to
// hash(AK_pub) at boot).
//
// The format is uniform across all bundle-mode vendors. The on-chain
// validation hook dispatches by the 4-byte magic "STBN" (0x5354424E) at
// offset 0; anything else falls through to the legacy raw-V4 path. The
// magic is mandatory — without it, tampering the trailing TPM bytes would
// be silently ignored by a verifier that parses the V4 header alone.
//
// All length fields are network byte order (big-endian uint32) so Solidity
// abi.decode-style readers can parse them with no byte-swap. Length sanity
// caps protect on-chain DoS surfaces.
//
// V4.report_data binding semantics (vendor-specific):
//
//  - Direct (configfs-tsm; GCP/bare-metal): the guest sets V4.report_data
//    to SHA256(AK_pub_DER) || zeros(32). RuntimeData is empty. The
//    verifier checks SHA256(bundle.AKPub) == V4.report_data[:32].
//
//  - Paravisor-mediated guest: the paravisor locks V4.report_data at
//    boot to SHA256(IGVM_REQUEST_DATA.VariableData), where VariableData
//    is a JSON blob containing the AK pub in JWK form (key id
//    "HCLAkPub") plus EK pub, vm-config, and a fixed user-data
//    placeholder. We cannot influence V4.report_data here, so the
//    kernel carries the VariableData blob inside the bundle as
//    RuntimeData and the verifier checks SHA256(bundle.RuntimeData) ==
//    V4.report_data[:32]. Then the verifier parses the JWK to find
//    HCLAkPub.n and confirms the modulus matches bundle.AKPub. This
//    binds the AK to the V4 quote indirectly through the
//    paravisor-built JSON envelope.
//
// Wire layout (locked):
//
//   offset            size  field
//   ------            ----  -----
//   0                 4     magic = "STBN" (0x5354424E)
//   4                 1     version = 0x01
//   5                 1     flags  (bit0 TPM_PRESENT; bit1..7 reserved, MUST be 0)
//   6                 2     vendor_tag (0x0000 direct/GCP, 0x0001 paravisor, 0xFFFF test)
//   8                 4     tdx_v4_len   (BE uint32) = N
//   12                N     tdx_v4_quote bytes
//   12+N              4     tpm_attest_len (BE uint32) = M  (0 if TPM_PRESENT=0)
//   16+N              M     tpm_attest   TPMS_ATTEST blob (no TPM2B size prefix)
//   16+N+M            4     tpm_sig_len  (BE uint32) = K  (0 if TPM_PRESENT=0)
//   20+N+M            K     tpm_sig      TPMT_SIGNATURE blob (algId + hashAlg + sig)
//   20+N+M+K          4     ak_pub_len   (BE uint32) = L  (0 if TPM_PRESENT=0)
//   24+N+M+K          L     ak_pub       DER SubjectPublicKeyInfo
//   24+N+M+K+L        4     runtime_data_len (BE uint32) = R
//   28+N+M+K+L        R     runtime_data (paravisor: VariableData JSON blob;
//                            direct: empty. R MUST be 0 when vendor_tag is
//                            VendorTagDirect, MUST be > 0 when
//                            vendor_tag is VendorTagParavisor.)
//
// =============================================================================

// Bundle constants — magic, version, flags, vendor tags, length caps. The
// caps prevent an attacker from forcing an on-chain parser to allocate
// large temporaries; they also protect the kernel's own self-check.
const (
	// BundleMagic is the four-byte discriminator at offset 0. It must be
	// distinguishable from a raw V4 quote (which starts with
	// little-endian uint16 version=4 → bytes 0x04 0x00) so a pre-Path-B
	// chain rejects bundles loudly instead of misparsing them.
	BundleMagic = "STBN"

	// BundleVersion is the only currently accepted version. Any value
	// greater than this triggers "unsupported bundle version" at
	// unmarshal time. The version byte gives us a forward-compat slot for
	// future post-quantum AK schemes or extra evidence sections.
	BundleVersion uint8 = 0x01

	// FlagTPMPresent indicates that the bundle carries a TPM2_Quote
	// (TPMS_ATTEST + signature + AK pub). Both production vendors set
	// this. Bit1..7 are reserved and MUST be zero — any other set bit
	// fails the unmarshal check.
	FlagTPMPresent uint8 = 0x01

	flagsReservedMask uint8 = 0xFE // every bit except bit0 must be zero

	// Vendor tag values are diagnostic only. The on-chain verifier MUST
	// NOT condition trust on them; they are a hint for telemetry and
	// logs.
	VendorTagDirect    uint16 = 0x0000
	VendorTagParavisor uint16 = 0x0001
	VendorTagTest      uint16 = 0xFFFF

	// Length caps. These are enforced at marshal time (defense in depth)
	// and at unmarshal time (the load-bearing barrier against on-chain
	// DoS). Total bundle is capped at 64 KiB to keep verification gas
	// bounded.
	maxBundleSize      = 64 * 1024
	maxTDXV4Size       = 16 * 1024
	maxTPMAttestSize   = 4 * 1024
	maxTPMSigSize      = 1 * 1024
	maxAKPubSize       = 2 * 1024
	maxRuntimeDataSize = 4 * 1024 // paravisor VariableData empirically ~1.2 KB

	// bundleHeaderSize is the fixed prefix size up to and including the
	// tdx_v4_len field. Any input shorter than this fails fast before
	// any allocation.
	bundleHeaderSize = 12
)

// Bundle errors. Defined as package-level sentinels so callers can match
// with errors.Is — important for vendor adapters that want to fall through
// on benign decode failures (e.g., a still-pre-Path-B response).
var (
	ErrBundleTooShort       = errors.New("tdx: bundle too short")
	ErrBundleBadMagic       = errors.New("tdx: bundle has wrong magic")
	ErrBundleBadVersion     = errors.New("tdx: unsupported bundle version")
	ErrBundleBadFlags       = errors.New("tdx: bundle has reserved flag bits set")
	ErrBundleBadVendor      = errors.New("tdx: bundle has unknown vendor tag")
	ErrBundleLengthOver     = errors.New("tdx: bundle field exceeds size cap")
	ErrBundleLengthShort    = errors.New("tdx: bundle field length exceeds buffer")
	ErrBundleNoTPM          = errors.New("tdx: bundle has TPM sections without TPM_PRESENT flag")
	ErrBundleRuntimeMissing = errors.New("tdx: paravisor bundle missing runtime_data")
	ErrBundleRuntimeUnused  = errors.New("tdx: direct bundle must not carry runtime_data")
)

// Bundle is the parsed in-memory shape of a Path-B quote bundle. Slices
// are sub-slices of the input buffer; callers MUST treat the returned
// Bundle as read-only. The Marshal helper produces a fresh byte slice on
// every call so callers may mutate it freely.
type Bundle struct {
	Version   uint8
	Flags     uint8
	VendorTag uint16
	TdxV4     []byte
	TpmAttest []byte
	TpmSig    []byte
	AKPub     []byte
	// RuntimeData carries the vendor-specific blob whose SHA-256 hash
	// must equal V4.report_data[:32]. On paravisor-mediated guests this
	// is the IGVM_REQUEST_DATA.VariableData JSON envelope (HCLAkPub +
	// HCLEkPub + vm-config + user-data placeholder). On direct vendor
	// this is empty: V4.report_data[:32] is the kernel-controlled
	// SHA256(AKPub).
	RuntimeData []byte
}

// HasTPM reports whether the bundle carries a TPM2_Quote section. False
// means the bundle is V4-only (a future bare-metal-no-TPM vendor); the
// kernel's self-check rejects this combination today but the format
// reserves the bit for forward compatibility.
func (b *Bundle) HasTPM() bool { return b.Flags&FlagTPMPresent != 0 }

// MarshalBundle assembles the wire-format bundle from its components.
// flags must include FlagTPMPresent if any of attest/sig/akPub is non-
// empty. vendorTag is one of VendorTag*. runtimeData is the vendor-
// specific binding blob (paravisor: VariableData JSON; direct: empty).
// Length caps are enforced here so a misbehaving vendor adapter cannot
// ship oversized bundles.
//
// Returns a freshly allocated byte slice; the input slices are NOT
// retained.
func MarshalBundle(v4 []byte, attest []byte, sig []byte, akPubDER []byte, runtimeData []byte, flags uint8, vendorTag uint16) ([]byte, error) {
	if flags&flagsReservedMask != 0 {
		return nil, fmt.Errorf("%w: flags=0x%02x", ErrBundleBadFlags, flags)
	}
	switch vendorTag {
	case VendorTagDirect, VendorTagParavisor, VendorTagTest:
		// Accepted vendor tag.
	default:
		return nil, fmt.Errorf("%w: vendor_tag=0x%04x", ErrBundleBadVendor, vendorTag)
	}

	// Cap checks before allocation. Sizes are independent of TPM_PRESENT
	// state; absence (zero length) trivially satisfies all caps.
	if len(v4) > maxTDXV4Size {
		return nil, fmt.Errorf("%w: tdx_v4_len=%d cap=%d", ErrBundleLengthOver, len(v4), maxTDXV4Size)
	}
	if len(attest) > maxTPMAttestSize {
		return nil, fmt.Errorf("%w: tpm_attest_len=%d cap=%d", ErrBundleLengthOver, len(attest), maxTPMAttestSize)
	}
	if len(sig) > maxTPMSigSize {
		return nil, fmt.Errorf("%w: tpm_sig_len=%d cap=%d", ErrBundleLengthOver, len(sig), maxTPMSigSize)
	}
	if len(akPubDER) > maxAKPubSize {
		return nil, fmt.Errorf("%w: ak_pub_len=%d cap=%d", ErrBundleLengthOver, len(akPubDER), maxAKPubSize)
	}
	if len(runtimeData) > maxRuntimeDataSize {
		return nil, fmt.Errorf("%w: runtime_data_len=%d cap=%d", ErrBundleLengthOver, len(runtimeData), maxRuntimeDataSize)
	}

	// If TPM_PRESENT is unset, all TPM sections must be empty. This is
	// the marshal-side mirror of the unmarshal check in UnmarshalBundle.
	// The constraint is reciprocal: a bundle that omits the flag but
	// carries TPM bytes is malformed and must be rejected at both ends.
	if flags&FlagTPMPresent == 0 {
		if len(attest) != 0 || len(sig) != 0 || len(akPubDER) != 0 {
			return nil, fmt.Errorf("%w: have attest=%d sig=%d ak=%d but TPM_PRESENT=0",
				ErrBundleNoTPM, len(attest), len(sig), len(akPubDER))
		}
	}

	// Vendor-specific RuntimeData invariants. These mirror the on-chain
	// dispatch: a direct bundle has no envelope to bind, a paravisor
	// bundle MUST carry one (the V4.report_data is otherwise unbindable).
	switch vendorTag {
	case VendorTagDirect:
		if len(runtimeData) != 0 {
			return nil, fmt.Errorf("%w: direct vendor passed %d bytes", ErrBundleRuntimeUnused, len(runtimeData))
		}
	case VendorTagParavisor:
		if len(runtimeData) == 0 {
			return nil, ErrBundleRuntimeMissing
		}
	}

	total := bundleHeaderSize + len(v4) +
		4 + len(attest) +
		4 + len(sig) +
		4 + len(akPubDER) +
		4 + len(runtimeData)
	if total > maxBundleSize {
		return nil, fmt.Errorf("%w: total=%d cap=%d", ErrBundleLengthOver, total, maxBundleSize)
	}

	out := make([]byte, total)
	copy(out[0:4], BundleMagic)
	out[4] = BundleVersion
	out[5] = flags
	binary.BigEndian.PutUint16(out[6:8], vendorTag)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(v4)))

	off := 12
	copy(out[off:off+len(v4)], v4)
	off += len(v4)

	binary.BigEndian.PutUint32(out[off:off+4], uint32(len(attest)))
	off += 4
	copy(out[off:off+len(attest)], attest)
	off += len(attest)

	binary.BigEndian.PutUint32(out[off:off+4], uint32(len(sig)))
	off += 4
	copy(out[off:off+len(sig)], sig)
	off += len(sig)

	binary.BigEndian.PutUint32(out[off:off+4], uint32(len(akPubDER)))
	off += 4
	copy(out[off:off+len(akPubDER)], akPubDER)
	off += len(akPubDER)

	binary.BigEndian.PutUint32(out[off:off+4], uint32(len(runtimeData)))
	off += 4
	copy(out[off:off+len(runtimeData)], runtimeData)

	return out, nil
}

// UnmarshalBundle parses bundle bytes into a Bundle struct. It is fail-
// closed: any unknown magic, version, flag bit, vendor tag, or length-
// cap violation returns an error. The returned Bundle's slices alias the
// input buffer; callers that retain the bundle past the input's lifetime
// must clone the slices.
//
// All length fields are read big-endian. We perform the magic compare in
// constant time; the magic itself is public, but constant-time compare
// is hygiene that costs nothing here.
func UnmarshalBundle(in []byte) (*Bundle, error) {
	if len(in) > maxBundleSize {
		return nil, fmt.Errorf("%w: total=%d cap=%d", ErrBundleLengthOver, len(in), maxBundleSize)
	}
	if len(in) < bundleHeaderSize {
		return nil, fmt.Errorf("%w: have %d need %d header", ErrBundleTooShort, len(in), bundleHeaderSize)
	}

	// Constant-time magic compare. Cheap-but-hygienic.
	if subtle.ConstantTimeCompare(in[0:4], []byte(BundleMagic)) != 1 {
		return nil, fmt.Errorf("%w: got %q", ErrBundleBadMagic, in[0:4])
	}
	version := in[4]
	if version != BundleVersion {
		return nil, fmt.Errorf("%w: %d", ErrBundleBadVersion, version)
	}
	flags := in[5]
	if flags&flagsReservedMask != 0 {
		return nil, fmt.Errorf("%w: flags=0x%02x", ErrBundleBadFlags, flags)
	}
	vendorTag := binary.BigEndian.Uint16(in[6:8])
	switch vendorTag {
	case VendorTagDirect, VendorTagParavisor, VendorTagTest:
		// Accepted vendor tag.
	default:
		return nil, fmt.Errorf("%w: vendor_tag=0x%04x", ErrBundleBadVendor, vendorTag)
	}

	tdxLen := binary.BigEndian.Uint32(in[8:12])
	if tdxLen > maxTDXV4Size {
		return nil, fmt.Errorf("%w: tdx_v4_len=%d cap=%d", ErrBundleLengthOver, tdxLen, maxTDXV4Size)
	}
	off := uint32(bundleHeaderSize)
	if uint64(off)+uint64(tdxLen)+4 > uint64(len(in)) {
		return nil, fmt.Errorf("%w: after tdx_v4 expected attest_len at %d", ErrBundleLengthShort, uint64(off)+uint64(tdxLen))
	}
	tdxV4 := in[off : off+tdxLen]
	off += tdxLen

	attestLen := binary.BigEndian.Uint32(in[off : off+4])
	if attestLen > maxTPMAttestSize {
		return nil, fmt.Errorf("%w: tpm_attest_len=%d cap=%d", ErrBundleLengthOver, attestLen, maxTPMAttestSize)
	}
	off += 4
	if uint64(off)+uint64(attestLen)+4 > uint64(len(in)) {
		return nil, fmt.Errorf("%w: after tpm_attest expected sig_len at %d", ErrBundleLengthShort, uint64(off)+uint64(attestLen))
	}
	attest := in[off : off+attestLen]
	off += attestLen

	sigLen := binary.BigEndian.Uint32(in[off : off+4])
	if sigLen > maxTPMSigSize {
		return nil, fmt.Errorf("%w: tpm_sig_len=%d cap=%d", ErrBundleLengthOver, sigLen, maxTPMSigSize)
	}
	off += 4
	if uint64(off)+uint64(sigLen)+4 > uint64(len(in)) {
		return nil, fmt.Errorf("%w: after tpm_sig expected ak_pub_len at %d", ErrBundleLengthShort, uint64(off)+uint64(sigLen))
	}
	sig := in[off : off+sigLen]
	off += sigLen

	akLen := binary.BigEndian.Uint32(in[off : off+4])
	if akLen > maxAKPubSize {
		return nil, fmt.Errorf("%w: ak_pub_len=%d cap=%d", ErrBundleLengthOver, akLen, maxAKPubSize)
	}
	off += 4
	if uint64(off)+uint64(akLen)+4 > uint64(len(in)) {
		return nil, fmt.Errorf("%w: after ak_pub expected runtime_data_len at %d", ErrBundleLengthShort, uint64(off)+uint64(akLen))
	}
	akPub := in[off : off+akLen]
	off += akLen

	rtLen := binary.BigEndian.Uint32(in[off : off+4])
	if rtLen > maxRuntimeDataSize {
		return nil, fmt.Errorf("%w: runtime_data_len=%d cap=%d", ErrBundleLengthOver, rtLen, maxRuntimeDataSize)
	}
	off += 4
	if uint64(off)+uint64(rtLen) > uint64(len(in)) {
		return nil, fmt.Errorf("%w: runtime_data end %d > buffer %d", ErrBundleLengthShort, uint64(off)+uint64(rtLen), len(in))
	}
	runtimeData := in[off : off+rtLen]
	off += rtLen

	// Trailing bytes are NOT silently accepted: any leftover indicates a
	// malformed input and we reject. Solidity verifiers will sum the
	// fields and check exact-fit; the kernel mirror that here.
	if int(off) != len(in) {
		return nil, fmt.Errorf("%w: %d bytes trailing", ErrBundleLengthShort, int(len(in))-int(off))
	}

	// Cross-field consistency: TPM_PRESENT=0 forbids any non-empty TPM
	// section. This check matches MarshalBundle's reciprocal check.
	if flags&FlagTPMPresent == 0 {
		if len(attest) != 0 || len(sig) != 0 || len(akPub) != 0 {
			return nil, fmt.Errorf("%w: have attest=%d sig=%d ak=%d but TPM_PRESENT=0",
				ErrBundleNoTPM, len(attest), len(sig), len(akPub))
		}
	}

	// Vendor-specific RuntimeData invariants. Mirrors MarshalBundle.
	switch vendorTag {
	case VendorTagDirect:
		if len(runtimeData) != 0 {
			return nil, fmt.Errorf("%w: direct vendor carried %d bytes", ErrBundleRuntimeUnused, len(runtimeData))
		}
	case VendorTagParavisor:
		if len(runtimeData) == 0 {
			return nil, ErrBundleRuntimeMissing
		}
	}

	return &Bundle{
		Version:     version,
		Flags:       flags,
		VendorTag:   vendorTag,
		TdxV4:       tdxV4,
		TpmAttest:   attest,
		TpmSig:      sig,
		AKPub:       akPub,
		RuntimeData: runtimeData,
	}, nil
}

// HasBundleMagic reports whether buf begins with the STBN magic. Useful
// for callers that want to dispatch raw-V4 vs bundle without a full parse.
// Constant-time compare; safe on adversary-controlled input.
func HasBundleMagic(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	return subtle.ConstantTimeCompare(buf[0:4], []byte(BundleMagic)) == 1
}
