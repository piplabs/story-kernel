package tdx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// =============================================================================
// Seal/Unseal round-trip tests
// =============================================================================

// computeBootstrapDigest reads the simulator's current PCR digest for the
// configured PCRs. Used to convert a bootstrap-mode provider into a
// strict-mode provider for tests.
func computeBootstrapDigest(t *testing.T, tpm TPMDevice, pcrs []int) []byte {
	t.Helper()
	d, err := readCurrentPCRDigest(tpm, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrs})
	require.NoError(t, err)
	return d
}

func TestSealUnseal_RoundTrip_Bootstrap(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}

	plaintext := []byte("hello tdx sealing world")
	blob, err := tdxSeal(tpm, plaintext, providers)
	require.NoError(t, err)
	require.NotEmpty(t, blob)

	// Header bootstrap_flag must be 0x01 in bootstrap mode.
	require.Equal(t, byte(0x01), blob[hdrOffBootstrap])

	got, err := tdxUnseal(tpm, blob, providers)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestSealUnseal_RoundTrip_SingleProvider(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	digest := computeBootstrapDigest(t, tpm, []int{7, 11})
	providers := []ProviderPolicy{
		{Name: "strict", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: digest},
	}

	for _, n := range []int{0, 1, 64, 1024, 4096} {
		plaintext := make([]byte, n)
		_, _ = rand.Read(plaintext)

		blob, err := tdxSeal(tpm, plaintext, providers)
		require.NoError(t, err)
		require.Equal(t, byte(0x00), blob[hdrOffBootstrap], "single-provider mode must not set bootstrap flag")

		got, err := tdxUnseal(tpm, blob, providers)
		require.NoError(t, err)
		// bytes.Equal treats nil and empty slice as equal; testify's
		// require.Equal does not. AES-GCM.Open returns nil for an empty
		// ciphertext plaintext.
		require.True(t, bytes.Equal(plaintext, got),
			"size %d: round-trip mismatch", n)
	}
}

func TestSealUnseal_RoundTrip_MultiProvider(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	digest := computeBootstrapDigest(t, tpm, []int{7, 11})
	otherDigest := bytes.Repeat([]byte{0xCD}, 32)
	providers := []ProviderPolicy{
		{Name: "match", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: digest},
		{Name: "other", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: otherDigest},
	}

	plaintext := []byte("multi-branch policy or")
	blob, err := tdxSeal(tpm, plaintext, providers)
	require.NoError(t, err)
	got, err := tdxUnseal(tpm, blob, providers)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestSealUnseal_RoundTrip_MultiProvider_SecondBranchMatches verifies that
// PolicyOR resolves successfully when the FIRST branch's expected digest does
// not match the current PCR state but a LATER branch does. This guards
// against a regression where the unseal logic short-circuits on the first
// branch attempt rather than letting PolicyOR cover all populated branches.
func TestSealUnseal_RoundTrip_MultiProvider_SecondBranchMatches(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	matchingDigest := computeBootstrapDigest(t, tpm, []int{7, 11})
	wrongDigest := bytes.Repeat([]byte{0xCC}, 32)
	providers := []ProviderPolicy{
		{Name: "wrong-first", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrongDigest},
		{Name: "match-second", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: matchingDigest},
	}
	plaintext := []byte("second-branch-failover")
	blob, err := tdxSeal(tpm, plaintext, providers)
	require.NoError(t, err)
	got, err := tdxUnseal(tpm, blob, providers)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestSealUnseal_RoundTrip_MultiProvider_ThirdBranchMatches is a
// stronger regression than the two-branch variant: it confirms the
// unseal refactor walks the entire populated set looking for a match
// rather than short-circuiting after the first or second non-match.
// Three branches with only the third matching exercises the full
// matching loop and the trial-digest computation across every entry.
func TestSealUnseal_RoundTrip_MultiProvider_ThirdBranchMatches(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	matchingDigest := computeBootstrapDigest(t, tpm, []int{7, 11})
	wrongA := bytes.Repeat([]byte{0xCC}, 32)
	wrongB := bytes.Repeat([]byte{0xDD}, 32)
	providers := []ProviderPolicy{
		{Name: "wrong-first", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrongA},
		{Name: "wrong-second", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrongB},
		{Name: "match-third", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: matchingDigest},
	}
	plaintext := []byte("third-branch-failover")
	blob, err := tdxSeal(tpm, plaintext, providers)
	require.NoError(t, err)
	got, err := tdxUnseal(tpm, blob, providers)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestSealUnseal_MultiProvider_AllBranchesFail_RejectsUnseal verifies the
// fail-closed behavior of multi-branch unseal: if no provider's expected
// digest matches the current PCR state, the TPM rejects the unseal.
// This is the negative companion to TestSealUnseal_RoundTrip_MultiProvider_SecondBranchMatches.
func TestSealUnseal_MultiProvider_AllBranchesFail_RejectsUnseal(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	wrongA := bytes.Repeat([]byte{0xAA}, 32)
	wrongB := bytes.Repeat([]byte{0xBB}, 32)
	matching := computeBootstrapDigest(t, tpm, []int{7, 11})
	sealProviders := []ProviderPolicy{
		{Name: "match", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: matching},
	}
	blob, err := tdxSeal(tpm, []byte("payload"), sealProviders)
	require.NoError(t, err)
	// Now attempt unseal with both providers wrong.
	unsealProviders := []ProviderPolicy{
		{Name: "wrong-a", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrongA},
		{Name: "wrong-b", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: wrongB},
	}
	_, err = tdxUnseal(tpm, blob, unsealProviders)
	require.Error(t, err, "unseal must fail when no provider digest matches current PCRs")
}

func TestBuildSealPolicy_RejectsNonCanonicalHash(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	// Any provider whose Hash differs from pcrPolicyHash (the fixed SHA-256
	// bank) is rejected — not just heterogeneous sets.
	providers := []ProviderPolicy{
		{Name: "a", PCRSelection: tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{7}}, ExpectedDigest: bytes.Repeat([]byte{1}, 32)},
		{Name: "b", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{8}}, ExpectedDigest: bytes.Repeat([]byte{2}, 20)},
	}
	_, _, err := buildSealPolicy(tpm, providers)
	require.ErrorContains(t, err, "!= pcrPolicyHash")
}

func TestBuildSealPolicy_NoProviders(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	_, _, err := buildSealPolicy(tpm, nil)
	require.ErrorContains(t, err, "no providers configured")
}

func TestSeal_LargePayloadRespectsLimit(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}

	// 50 KiB succeeds.
	ok := make([]byte, 50*1024)
	_, _ = rand.Read(ok)
	_, err := tdxSeal(tpm, ok, providers)
	require.NoError(t, err)

	// 70 KiB exceeds uint16 wire limit.
	tooBig := make([]byte, 70*1024)
	_, err = tdxSeal(tpm, tooBig, providers)
	require.ErrorIs(t, err, errCiphertextOverflow)
}

// =============================================================================
// Wire-format error paths
// =============================================================================

func TestUnseal_TooShort(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	_, err := tdxUnseal(tpm, []byte{0x01, 0x02}, supportedProviders)
	require.ErrorIs(t, err, errSealedBlobTooShort)
}

func TestUnseal_BadMagic(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	bad := make([]byte, sealedBlobHeaderLen+10)
	copy(bad, "BAD!")
	_, err := tdxUnseal(tpm, bad, supportedProviders)
	require.ErrorIs(t, err, errSealedBlobBadMagic)
}

func TestUnseal_UnsupportedVersion(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	bad := make([]byte, sealedBlobHeaderLen+10)
	copy(bad[hdrOffMagic:], sealedBlobMagic)
	binary.BigEndian.PutUint16(bad[hdrOffVersion:], 99)
	_, err := tdxUnseal(tpm, bad, supportedProviders)
	require.ErrorIs(t, err, errSealedBlobBadVersion)
}

func TestUnseal_LengthMismatch(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	blob, err := tdxSeal(tpm, []byte("hello"), providers)
	require.NoError(t, err)

	// Truncate 1 byte off the end.
	bad := blob[:len(blob)-1]
	_, err = tdxUnseal(tpm, bad, providers)
	require.ErrorIs(t, err, errSealedBlobLengthMismatch)
}

func TestUnseal_TamperedHeader(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	blob, err := tdxSeal(tpm, []byte("hello"), providers)
	require.NoError(t, err)

	// Flip provider_count byte; AAD-bound GCM tag will reject.
	tampered := append([]byte(nil), blob...)
	tampered[hdrOffProviderCount] ^= 0xFF
	_, err = tdxUnseal(tpm, tampered, providers)
	require.Error(t, err)
	require.NotErrorIs(t, err, errSealedBlobLengthMismatch,
		"length is unchanged so the failure must come from AES-GCM")
}

func TestUnseal_TamperedCiphertext(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	blob, err := tdxSeal(tpm, []byte("hello"), providers)
	require.NoError(t, err)

	// Flip the last byte (inside the GCM tag); AES-GCM Open must fail.
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = tdxUnseal(tpm, tampered, providers)
	require.Error(t, err)
}

// =============================================================================
// Header layout invariants
// =============================================================================

func TestSealedBlob_HeaderStructure(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	plaintext := []byte("hello")
	blob, err := tdxSeal(tpm, plaintext, providers)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(blob), sealedBlobHeaderLen)

	require.Equal(t, sealedBlobMagic, string(blob[hdrOffMagic:hdrOffMagic+4]))
	require.Equal(t, sealedBlobVersion, binary.BigEndian.Uint16(blob[hdrOffVersion:]))
	require.Equal(t, byte(1), blob[hdrOffProviderCount], "single test provider")

	cipherLen := int(binary.BigEndian.Uint16(blob[hdrOffCipherLen:]))
	require.Equal(t, len(plaintext)+aesGCMTagLen, cipherLen)
}

// =============================================================================
// PCR digest helpers
// =============================================================================

func TestComputePCRDigest_SortedAndStable(t *testing.T) {
	t.Parallel()
	values := map[int][]byte{
		7:  bytes.Repeat([]byte{0xAA}, 32),
		11: bytes.Repeat([]byte{0xBB}, 32),
	}
	d1 := computePCRDigest(tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, 11}}, values)
	d2 := computePCRDigest(tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{11, 7}}, values)
	require.Equal(t, d1, d2, "computePCRDigest must sort PCR indexes")
	require.Len(t, d1, 32)
}

// TestComputePCRDigest_UnsupportedHashAlg_Panics asserts the contract that
// a hashAlg outside the supported switch panics rather than silently
// returning a nil digest. A nil digest would disable PCR binding in
// PolicyPCR (zero-length digest matches anything in TPM2's policy logic).
func TestComputePCRDigest_UnsupportedHashAlg_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		require.NotNil(t, r, "computePCRDigest must panic on unsupported hash algorithm")
		msg, ok := r.(string)
		require.True(t, ok, "panic value must be a string, got %T", r)
		require.Contains(t, msg, "unsupported hash algorithm",
			"panic message must name the failure mode")
	}()
	// AlgSHA1 is intentionally not wired into computePCRDigest's switch.
	_ = computePCRDigest(tpm2.PCRSelection{Hash: tpm2.AlgSHA1}, nil)
	t.Fatal("computePCRDigest returned without panicking")
}

// =============================================================================
// failClosedTPM
// =============================================================================

func TestFailClosedTPM_PropagatesError(t *testing.T) {
	t.Parallel()
	tpm := failClosedTPM{err: errSealedBlobTooShort} // any sentinel
	_, err := tpm.Read(make([]byte, 1))
	require.Error(t, err)
	_, err = tpm.Write([]byte{1})
	require.Error(t, err)
	require.NoError(t, tpm.Close())
}

// =============================================================================
// Seal/Unseal dispatch tests
//
// Exercise the package-level shims SealToFile / UnsealFromFile against the
// fail-closed stub backend on hosts without TDX silicon or a TPM device.
// Skip on real hardware where the calls would succeed.
// =============================================================================

// TestTDX_SealToFile_FailsClosed_NoFileLeft verifies that SealToFile returns
// an error AND does not leave a partially-written file behind when the seal
// step fails (fail-closed stub backend).
func TestTDX_SealToFile_FailsClosed_NoFileLeft(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	target := filepath.Join(t.TempDir(), "sealed.bin")
	require.Error(t, enclave.SealToFile([]byte("plaintext"), target))
	_, statErr := os.Stat(target)
	require.True(t, os.IsNotExist(statErr),
		"failed seal must not leave a file at %q", target)
}

// TestTDX_UnsealFromFile_MissingFile exercises the file-read step of
// UnsealFromFile, which runs before any sealing primitive is invoked. A
// missing file must surface as a wrapped read error rather than a confusing
// seal-layer error. Runs on any host because it never reaches the unseal call.
func TestTDX_UnsealFromFile_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := enclave.UnsealFromFile(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read")
}

// TestTDX_UnsealFromFile_FailsClosed verifies that an existing file with
// non-sealed content fails at the unseal step on a fail-closed stub
// backend. Skips on real hardware where the unseal would attempt a real
// (and still failing) TPM operation rather than the stub error.
func TestTDX_UnsealFromFile_FailsClosed(t *testing.T) {
	t.Parallel()
	if !onFailClosedHost(t) {
		t.Skip("real TDX host; skipping fail-closed shim assertion")
	}
	target := filepath.Join(t.TempDir(), "blob.bin")
	require.NoError(t, os.WriteFile(target, []byte("not actually sealed"), 0600))
	_, err := enclave.UnsealFromFile(target)
	require.Error(t, err)
}

// TestUnseal_CorruptedSealedObject_FailsClosed flips a byte inside the
// TPM-sealed object (priv region) — distinct from the header (AAD-bound) and
// ciphertext (GCM-tag) tamper tests. TPM2_Load / Unseal must reject it, and
// the error must be surfaced (not swallowed).
func TestUnseal_CorruptedSealedObject_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	blob, err := tdxSeal(tpm, []byte("hello"), providers)
	require.NoError(t, err)

	privLen := int(binary.BigEndian.Uint16(blob[hdrOffPrivLen : hdrOffPrivLen+2]))
	require.Positive(t, privLen)
	tampered := append([]byte(nil), blob...)
	tampered[sealedBlobHeaderLen+privLen/2] ^= 0x01 // flip a byte mid-priv
	_, err = tdxUnseal(tpm, tampered, providers)
	require.Error(t, err)
}

// TestUnseal_BootstrapPCRChanged_FailsClosed is the core sealing security
// property: a blob sealed to a PCR state cannot be unsealed once a bound PCR
// changes. Seal in bootstrap mode, extend a bound PCR, then unseal — the TPM
// must refuse.
func TestUnseal_BootstrapPCRChanged_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	providers := []ProviderPolicy{
		{Name: "test", PCRSelection: tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	blob, err := tdxSeal(tpm, []byte("secret"), providers)
	require.NoError(t, err)

	// Change PCR 7 (one of the bound PCRs) after sealing.
	extendPCR(t, tpm, 7, []byte("state change"))

	_, err = tdxUnseal(tpm, blob, providers)
	require.Error(t, err, "unseal must fail closed after a bound PCR changed")
}

// TestUnseal_StrictBlobOnBootstrapHost_FailsClosed covers the diagnostic guard:
// a blob sealed in STRICT mode (bootstrap flag clear) but unsealed on a host
// whose providers carry no ExpectedDigest must return a clear mismatch error,
// not silently take the bootstrap path.
func TestUnseal_StrictBlobOnBootstrapHost_FailsClosed(t *testing.T) {
	t.Parallel()
	tpm := newTestTPM(t)
	digest := computeBootstrapDigest(t, tpm, []int{7, 11})
	strict := []ProviderPolicy{
		{Name: "strict", PCRSelection: tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{7, 11}}, ExpectedDigest: digest},
	}
	blob, err := tdxSeal(tpm, []byte("payload"), strict)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), blob[hdrOffBootstrap])

	// Host configured for bootstrap (no ExpectedDigest) sees a strict blob.
	bootstrap := []ProviderPolicy{
		{Name: "boot", PCRSelection: tpm2.PCRSelection{Hash: pcrPolicyHash, PCRs: []int{7, 11}}, ExpectedDigest: nil},
	}
	_, err = tdxUnseal(tpm, blob, bootstrap)
	require.ErrorContains(t, err, "sealed in strict mode")
}
