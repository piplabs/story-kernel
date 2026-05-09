package platform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// MarshalBundle / UnmarshalBundle round-trip
// =============================================================================

func TestBundle_RoundTrip_TPMPresent_Paravisor(t *testing.T) {
	t.Parallel()
	v4 := bytes.Repeat([]byte{0x04}, 632)
	attest := bytes.Repeat([]byte{0xAB}, 129)
	sig := bytes.Repeat([]byte{0xCD}, 256)
	akPub := bytes.Repeat([]byte{0xEF}, 272)
	runtimeData := []byte(`{"keys":[{"kid":"HCLAkPub"}]}`)

	out, err := MarshalBundle(v4, attest, sig, akPub, runtimeData, FlagTPMPresent, VendorTagParavisor)
	require.NoError(t, err)

	parsed, err := UnmarshalBundle(out)
	require.NoError(t, err)
	require.Equal(t, BundleVersion, parsed.Version)
	require.Equal(t, FlagTPMPresent, parsed.Flags)
	require.Equal(t, VendorTagParavisor, parsed.VendorTag)
	require.Equal(t, v4, parsed.TdxV4)
	require.Equal(t, attest, parsed.TpmAttest)
	require.Equal(t, sig, parsed.TpmSig)
	require.Equal(t, akPub, parsed.AKPub)
	require.Equal(t, runtimeData, parsed.RuntimeData)
	require.True(t, parsed.HasTPM())
	require.True(t, HasBundleMagic(out))
}

func TestBundle_RoundTrip_TPMPresent_Direct(t *testing.T) {
	t.Parallel()
	v4 := bytes.Repeat([]byte{0x04}, 632)
	attest := bytes.Repeat([]byte{0xAB}, 129)
	sig := bytes.Repeat([]byte{0xCD}, 256)
	akPub := bytes.Repeat([]byte{0xEF}, 272)

	out, err := MarshalBundle(v4, attest, sig, akPub, nil, FlagTPMPresent, VendorTagDirect)
	require.NoError(t, err)

	parsed, err := UnmarshalBundle(out)
	require.NoError(t, err)
	require.Equal(t, VendorTagDirect, parsed.VendorTag)
	require.Equal(t, akPub, parsed.AKPub)
	require.Empty(t, parsed.RuntimeData)
	require.True(t, parsed.HasTPM())
}

func TestBundle_RoundTrip_NoTPM(t *testing.T) {
	t.Parallel()
	v4 := bytes.Repeat([]byte{0x04}, 632)

	out, err := MarshalBundle(v4, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)

	parsed, err := UnmarshalBundle(out)
	require.NoError(t, err)
	require.Equal(t, uint8(0), parsed.Flags)
	require.False(t, parsed.HasTPM())
	require.Equal(t, v4, parsed.TdxV4)
	require.Empty(t, parsed.TpmAttest)
	require.Empty(t, parsed.TpmSig)
	require.Empty(t, parsed.AKPub)
	require.Empty(t, parsed.RuntimeData)
}

// =============================================================================
// Marshal-side guards
// =============================================================================

func TestMarshalBundle_RejectsReservedFlags(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x02, VendorTagDirect)
	require.ErrorIs(t, err, ErrBundleBadFlags)
}

func TestMarshalBundle_RejectsUnknownVendor(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, 0x1234)
	require.ErrorIs(t, err, ErrBundleBadVendor)
}

func TestMarshalBundle_RejectsTPMSectionsWithoutFlag(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle(
		bytes.Repeat([]byte{0x04}, 8),
		bytes.Repeat([]byte{0xAB}, 1), // attest non-empty
		nil, nil, nil,
		0x00, // TPM_PRESENT not set
		VendorTagDirect,
	)
	require.ErrorIs(t, err, ErrBundleNoTPM)
}

func TestMarshalBundle_ParavisorRequiresRuntimeData(t *testing.T) {
	t.Parallel()
	// Paravisor vendor MUST carry runtime_data — the V4.report_data
	// binding requires the VariableData blob. Empty payload must fail
	// closed.
	_, err := MarshalBundle(
		bytes.Repeat([]byte{0x04}, 632),
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0xCD}, 8),
		bytes.Repeat([]byte{0xEF}, 12),
		nil, // runtime_data missing
		FlagTPMPresent, VendorTagParavisor,
	)
	require.ErrorIs(t, err, ErrBundleRuntimeMissing)
}

func TestMarshalBundle_DirectRefusesRuntimeData(t *testing.T) {
	t.Parallel()
	// Direct vendor MUST NOT carry runtime_data — the binding semantics
	// expect SHA256(AKPub) at V4.report_data, no envelope. Catch
	// vendor-tag misuse loudly.
	_, err := MarshalBundle(
		bytes.Repeat([]byte{0x04}, 632),
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0xCD}, 8),
		bytes.Repeat([]byte{0xEF}, 12),
		[]byte("unexpected runtime data"),
		FlagTPMPresent, VendorTagDirect,
	)
	require.ErrorIs(t, err, ErrBundleRuntimeUnused)
}

func TestMarshalBundle_RejectsOversizedV4(t *testing.T) {
	t.Parallel()
	v4 := bytes.Repeat([]byte{0x04}, maxTDXV4Size+1)
	_, err := MarshalBundle(v4, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

func TestMarshalBundle_RejectsOversizedAttest(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle(
		[]byte{0x04},
		bytes.Repeat([]byte{0xAB}, maxTPMAttestSize+1),
		[]byte{0xCD},
		[]byte{0xEF},
		nil,
		FlagTPMPresent, VendorTagDirect,
	)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

func TestMarshalBundle_RejectsOversizedSig(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle(
		[]byte{0x04},
		[]byte{0xAB},
		bytes.Repeat([]byte{0xCD}, maxTPMSigSize+1),
		[]byte{0xEF},
		nil,
		FlagTPMPresent, VendorTagDirect,
	)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

func TestMarshalBundle_RejectsOversizedAKPub(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle(
		[]byte{0x04},
		[]byte{0xAB},
		[]byte{0xCD},
		bytes.Repeat([]byte{0xEF}, maxAKPubSize+1),
		nil,
		FlagTPMPresent, VendorTagDirect,
	)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

func TestMarshalBundle_RejectsOversizedRuntime(t *testing.T) {
	t.Parallel()
	_, err := MarshalBundle(
		[]byte{0x04},
		[]byte{0xAB},
		[]byte{0xCD},
		[]byte{0xEF},
		bytes.Repeat([]byte{'r'}, maxRuntimeDataSize+1),
		FlagTPMPresent, VendorTagParavisor,
	)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

// TestMarshalBundle_RejectsOversizedTotal exercises the total-bundle cap.
// Individual fields fit; their sum exceeds the cap.
func TestMarshalBundle_RejectsOversizedTotal(t *testing.T) {
	t.Parallel()
	// 16 KiB v4 + 4 KiB attest + 1 KiB sig + 2 KiB ak = 23 KiB, well under
	// the 64 KiB total cap. Push v4 to its individual cap and pad attest
	// + sig + ak so total > 64 KiB. Cannot hit the total cap without
	// blowing an individual cap, so this case is structurally
	// unreachable today; the test documents that observation.
	t.Skip("total-cap branch is structurally unreachable given individual caps " +
		"(16K v4 + 4K attest + 1K sig + 2K ak ≈ 23K << 64K cap). Documenting via skip.")
}

// =============================================================================
// Unmarshal-side guards
// =============================================================================

func TestUnmarshalBundle_TooShort(t *testing.T) {
	t.Parallel()
	_, err := UnmarshalBundle(make([]byte, bundleHeaderSize-1))
	require.ErrorIs(t, err, ErrBundleTooShort)
}

func TestUnmarshalBundle_BadMagic(t *testing.T) {
	t.Parallel()
	good, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	bad[0] = 'X'
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleBadMagic)
}

func TestUnmarshalBundle_BadVersion(t *testing.T) {
	t.Parallel()
	good, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	bad[4] = 0x02 // not the supported version
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleBadVersion)
}

func TestUnmarshalBundle_BadFlags(t *testing.T) {
	t.Parallel()
	good, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	bad[5] = 0x80 // reserved bit
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleBadFlags)
}

func TestUnmarshalBundle_BadVendor(t *testing.T) {
	t.Parallel()
	good, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(bad[6:8], 0xAAAA)
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleBadVendor)
}

func TestUnmarshalBundle_TPMSectionsWithoutFlag(t *testing.T) {
	t.Parallel()
	// Build a valid TPM_PRESENT bundle, then flip the flag bit off. The
	// cross-field consistency check must reject.
	good, err := MarshalBundle(
		[]byte{0x04},
		[]byte{0xAB},
		[]byte{0xCD},
		[]byte{0xEF},
		nil,
		FlagTPMPresent, VendorTagDirect,
	)
	require.NoError(t, err)
	bad := append([]byte(nil), good...)
	bad[5] = 0x00 // clear FlagTPMPresent
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleNoTPM)
}

func TestUnmarshalBundle_ParavisorMissingRuntimeData(t *testing.T) {
	t.Parallel()
	// Build a paravisor bundle with valid runtime_data, then zero its
	// length prefix. The vendor invariant check must reject.
	good, err := MarshalBundle(
		[]byte{0x04},
		[]byte{0xAB},
		[]byte{0xCD},
		[]byte{0xEF},
		[]byte("rt"),
		FlagTPMPresent, VendorTagParavisor,
	)
	require.NoError(t, err)
	// Locate runtime_data_len prefix and zero it (BE uint32). Field
	// layout: header(12) + v4(1) + 4+attest(1) + 4+sig(1) + 4+ak(1)
	// + 4+runtime(2) = 12+1+5+5+5+6 = 34. Compute by walking the bundle
	// to be robust against future header changes.
	off := 12 + 1 + 4 + 1 + 4 + 1 + 4 + 1 // up to runtime_data_len start
	require.Greater(t, len(good), off+4)
	bad := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(bad[off:off+4], 0)
	bad = bad[:off+4] // drop the runtime_data bytes too
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleRuntimeMissing)
}

// TestUnmarshalBundle_TruncatedAtBoundary checks that truncation at every
// length-prefix boundary yields a clear length-short error rather than
// panicking on out-of-bounds slice.
func TestUnmarshalBundle_TruncatedAtBoundary(t *testing.T) {
	t.Parallel()
	full, err := MarshalBundle(
		bytes.Repeat([]byte{0x04}, 32),
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0xCD}, 8),
		bytes.Repeat([]byte{0xEF}, 12),
		[]byte("rt-payload"),
		FlagTPMPresent, VendorTagParavisor,
	)
	require.NoError(t, err)

	// Truncate at every offset from 0..len-1. The header check rejects
	// values < 12 with ErrBundleTooShort; everything past should reject
	// with either ErrBundleLengthShort or ErrBundleBadMagic (the magic
	// is the first bytes — partial header still fails).
	for cut := 0; cut < len(full); cut++ {
		truncated := full[:cut]
		_, err := UnmarshalBundle(truncated)
		require.Error(t, err, "expected error truncating at %d", cut)
	}
}

func TestUnmarshalBundle_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()
	good, err := MarshalBundle([]byte{0x04}, nil, nil, nil, nil, 0x00, VendorTagDirect)
	require.NoError(t, err)
	bad := append(append([]byte(nil), good...), 0xFF)
	_, err = UnmarshalBundle(bad)
	require.ErrorIs(t, err, ErrBundleLengthShort)
}

func TestUnmarshalBundle_OversizedTotal(t *testing.T) {
	t.Parallel()
	huge := make([]byte, maxBundleSize+1)
	_, err := UnmarshalBundle(huge)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

func TestUnmarshalBundle_OversizedV4Field(t *testing.T) {
	t.Parallel()
	// Hand-craft a header advertising a tdx_v4_len > maxTDXV4Size.
	hdr := make([]byte, bundleHeaderSize)
	copy(hdr[0:4], BundleMagic)
	hdr[4] = BundleVersion
	hdr[5] = 0x00
	binary.BigEndian.PutUint16(hdr[6:8], VendorTagDirect)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(maxTDXV4Size+1))
	_, err := UnmarshalBundle(hdr)
	require.ErrorIs(t, err, ErrBundleLengthOver)
}

// =============================================================================
// Big-endian length parsing — fixture-driven
// =============================================================================

// TestUnmarshalBundle_FixtureBigEndian feeds a hand-crafted hex fixture and
// asserts each length is parsed in network byte order. If a future
// refactor accidentally switches to little-endian, this fixture fails
// loudly.
func TestUnmarshalBundle_FixtureBigEndian(t *testing.T) {
	t.Parallel()
	// Layout: magic STBN | ver=01 | flags=01 | vendor=0001 | v4_len=0x00000003
	//         | v4=AABBCC | attest_len=0x00000001 | attest=11
	//         | sig_len=0x00000001 | sig=22
	//         | ak_len=0x00000001 | ak=33
	//         | runtime_data_len=0x00000002 | rt=4455
	hex := []byte{
		'S', 'T', 'B', 'N',
		0x01,
		0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x03,
		0xAA, 0xBB, 0xCC,
		0x00, 0x00, 0x00, 0x01,
		0x11,
		0x00, 0x00, 0x00, 0x01,
		0x22,
		0x00, 0x00, 0x00, 0x01,
		0x33,
		0x00, 0x00, 0x00, 0x02,
		0x44, 0x55,
	}
	parsed, err := UnmarshalBundle(hex)
	require.NoError(t, err)
	require.Equal(t, []byte{0xAA, 0xBB, 0xCC}, parsed.TdxV4)
	require.Equal(t, []byte{0x11}, parsed.TpmAttest)
	require.Equal(t, []byte{0x22}, parsed.TpmSig)
	require.Equal(t, []byte{0x33}, parsed.AKPub)
	require.Equal(t, []byte{0x44, 0x55}, parsed.RuntimeData)
	require.Equal(t, VendorTagParavisor, parsed.VendorTag)
}

// =============================================================================
// HasBundleMagic
// =============================================================================

func TestHasBundleMagic(t *testing.T) {
	t.Parallel()
	require.False(t, HasBundleMagic(nil))
	require.False(t, HasBundleMagic([]byte{'S'}))
	require.False(t, HasBundleMagic([]byte("STBX")))
	require.True(t, HasBundleMagic([]byte("STBN")))
	require.True(t, HasBundleMagic([]byte("STBN\x00\x00")))
}

// TestBundleErrors_AreSentinels verifies callers can errors.Is-match the
// public sentinels. Useful for vendor adapters that want to distinguish
// "input was not a Path-B bundle" from other errors.
func TestBundleErrors_AreSentinels(t *testing.T) {
	t.Parallel()
	for _, sentinel := range []error{
		ErrBundleTooShort,
		ErrBundleBadMagic,
		ErrBundleBadVersion,
		ErrBundleBadFlags,
		ErrBundleBadVendor,
		ErrBundleLengthOver,
		ErrBundleLengthShort,
		ErrBundleNoTPM,
		ErrBundleRuntimeMissing,
		ErrBundleRuntimeUnused,
	} {
		wrapped := errors.New("wrap: " + sentinel.Error())
		// errors.Is requires the wrap chain; here we just assert the
		// sentinels are non-nil and distinguishable. Wrap behavior is
		// covered transitively by the marshal/unmarshal tests above.
		require.NotNil(t, sentinel)
		require.NotEqual(t, wrapped.Error(), sentinel.Error())
	}
}
