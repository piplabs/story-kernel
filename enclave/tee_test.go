package enclave_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// fakeBackend is a deterministic test stub that exercises every TEE method
// without depending on a real TEE platform.
type fakeBackend struct {
	name string
	// identity, when non-nil, overrides the default GetSelfIdentity payload.
	// Lets a single test seed an arbitrary Identity (e.g. a TDX-shaped one)
	// without needing a separate backend type.
	identity *enclave.Identity
}

func (b fakeBackend) Backend() string { return b.name }

func (b fakeBackend) GetRemoteQuote(d []byte) ([]byte, error) {
	out := append([]byte("quote:"), d...)
	return out, nil
}

func (b fakeBackend) GetSelfIdentity() (*enclave.Identity, error) {
	if b.identity != nil {
		return b.identity, nil
	}
	return &enclave.Identity{
		Type:           enclave.IdentityUnknown,
		CodeCommitment: []byte("self"),
		ProductID:      []byte{0x00, 0x01},
	}, nil
}

func (b fakeBackend) GetSelfCodeCommitment() ([]byte, error) {
	return []byte("self"), nil
}

func (b fakeBackend) ValidateCodeCommitment(c []byte) error {
	if string(c) == "self" {
		return nil
	}
	return errors.New("mismatch")
}

func (b fakeBackend) Seal(p []byte) ([]byte, error) {
	return append([]byte("sealed:"), p...), nil
}

func (b fakeBackend) Unseal(s []byte) ([]byte, error) {
	const prefix = "sealed:"
	if len(s) < len(prefix) || string(s[:len(prefix)]) != prefix {
		return nil, errors.New("not a sealed blob")
	}
	return s[len(prefix):], nil
}

func (b fakeBackend) NewSealedDB(_, _ string) (cmtdb.DB, error) { return nil, nil }

// errorBackend is a deterministic test stub whose every method returns the
// caller-configured error. It lets the shim-level error-propagation tests
// run without a real TEE platform.
type errorBackend struct {
	name        string
	sealErr     error
	unsealErr   error
	identityErr error
	quoteErr    error
	codeCommErr error
	validateErr error
}

func (b errorBackend) Backend() string { return b.name }

func (b errorBackend) GetRemoteQuote([]byte) ([]byte, error) {
	return nil, b.quoteErr
}

func (b errorBackend) GetSelfIdentity() (*enclave.Identity, error) {
	return nil, b.identityErr
}

func (b errorBackend) GetSelfCodeCommitment() ([]byte, error) {
	return nil, b.codeCommErr
}

func (b errorBackend) ValidateCodeCommitment([]byte) error {
	return b.validateErr
}

func (b errorBackend) Seal([]byte) ([]byte, error) {
	return nil, b.sealErr
}

func (b errorBackend) Unseal([]byte) ([]byte, error) {
	return nil, b.unsealErr
}

func (b errorBackend) NewSealedDB(_, _ string) (cmtdb.DB, error) {
	return nil, errors.New("errorBackend: NewSealedDB unsupported")
}

// Compile-time assertion that fakeBackend and errorBackend satisfy all the
// narrow interfaces and the composite TEE interface. If the interfaces
// drift, this file fails to build.
var (
	_ enclave.Sealer     = fakeBackend{}
	_ enclave.Quoter     = fakeBackend{}
	_ enclave.Identifier = fakeBackend{}
	_ enclave.TEE        = fakeBackend{}
	_ enclave.TEE        = errorBackend{}
)

func TestRegisterPanicsOnNil(t *testing.T) {
	require.Panics(t, func() { enclave.Register(nil) })
}

func TestShimFunctionsDelegate(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	// Quoter shim
	q, err := enclave.GetRemoteQuote([]byte("d"))
	require.NoError(t, err)
	require.Equal(t, []byte("quote:d"), q)

	// Identifier shims
	require.NoError(t, enclave.ValidateCodeCommitment([]byte("self")))
	require.Error(t, enclave.ValidateCodeCommitment([]byte("nope")))

	cc, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)
	require.Equal(t, []byte("self"), cc)

	info, err := enclave.GetSelfEnclaveInfo()
	require.NoError(t, err)
	require.Equal(t, []byte("self"), info.UniqueID)
	require.Equal(t, []byte{0x00, 0x01}, info.ProductID)
}

func TestSealToFileAndUnsealRoundTrip(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	dir := t.TempDir()
	path := dir + "/sealed.bin"
	require.NoError(t, enclave.SealToFile([]byte("hello"), path))

	pt, err := enclave.UnsealFromFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

func TestUnsealFromFileMissingPath(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	_, err := enclave.UnsealFromFile(t.TempDir() + "/does-not-exist")
	require.Error(t, err)
}

func TestDefaultReturnsRegisteredBackend(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	require.Equal(t, "fake", enclave.Default().Backend())
}

func TestNewSealedLevelDBShimDelegates(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	db, err := enclave.NewSealedLevelDB("x", t.TempDir())
	require.NoError(t, err)
	// fakeBackend.NewSealedDB returns (nil, nil) by design.
	require.Nil(t, db)
}

// =============================================================================
// Register diagnostics
//
// Register's "called twice" branch is not exercised by the rest of the suite
// (production code calls Register exactly once at init). The test seeds an
// initial backend via SwapDefault, then attempts a second Register and asserts
// the panic text mentions both backend identifiers.
// =============================================================================

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "first"})
	defer restore()

	defer func() {
		r := recover()
		require.NotNil(t, r, "Register must panic when a backend is already installed")
		msg, ok := r.(string)
		require.True(t, ok, "panic value must be a string, got %T", r)
		require.Contains(t, msg, "Register called twice",
			"panic message must name the failure mode")
		require.Contains(t, msg, "first", "panic message must include the previously installed backend name")
		require.Contains(t, msg, "second", "panic message must include the newly attempted backend name")
	}()
	enclave.Register(fakeBackend{name: "second"})
	t.Fatal("Register returned without panicking")
}

// =============================================================================
// Shim error propagation
// =============================================================================

// TestSealToFile_SealError covers the Seal-failure branch of SealToFile. The
// errorBackend returns a synthetic Seal error; SealToFile must propagate it
// without writing the destination file.
func TestSealToFile_SealError(t *testing.T) {
	sealErr := errors.New("synthetic seal failure")
	restore := enclave.SwapDefault(errorBackend{name: "err", sealErr: sealErr})
	defer restore()

	dir := t.TempDir()
	dst := filepath.Join(dir, "must-not-exist.bin")

	err := enclave.SealToFile([]byte("payload"), dst)
	require.Error(t, err, "SealToFile must surface the Seal error")
	require.ErrorContains(t, err, "synthetic seal failure")

	// Sanity: the destination must NOT have been written.
	exists, statFailed := dirEntryExists(dst)
	require.False(t, statFailed, "stat returned a non-ENOENT error")
	require.False(t, exists, "SealToFile must not create the destination file when Seal fails")
}

// TestSealToFile_WriteError covers the os.WriteFile-failure branch. Asking
// the OS to write into a path under a non-existent directory triggers a real
// write error that we can assert is propagated as a wrapped error.
func TestSealToFile_WriteError(t *testing.T) {
	restore := enclave.SwapDefault(fakeBackend{name: "fake"})
	defer restore()

	// Path under a non-existent subdirectory; os.WriteFile returns ENOENT.
	dst := filepath.Join(t.TempDir(), "no-such-subdir", "out.bin")

	err := enclave.SealToFile([]byte("payload"), dst)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to write")
}

// TestUnsealFromFile_UnsealError covers the Unseal-failure branch of
// UnsealFromFile (file read succeeds but the backend rejects the blob).
func TestUnsealFromFile_UnsealError(t *testing.T) {
	restore := enclave.SwapDefault(errorBackend{name: "err", unsealErr: errors.New("synthetic unseal failure")})
	defer restore()

	// Pre-write a non-empty file so os.ReadFile succeeds.
	dir := t.TempDir()
	src := filepath.Join(dir, "blob.bin")
	require.NoError(t, writeFileForTest(src, []byte("opaque")))

	_, err := enclave.UnsealFromFile(src)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unseal")
}

// TestGetSelfEnclaveInfo_ErrorPropagates ensures the shim surfaces a backend
// identity error rather than silently returning a zero-valued EnclaveInfo.
func TestGetSelfEnclaveInfo_ErrorPropagates(t *testing.T) {
	idErr := errors.New("identity failure")
	restore := enclave.SwapDefault(errorBackend{name: "err", identityErr: idErr})
	defer restore()

	info, err := enclave.GetSelfEnclaveInfo()
	require.Error(t, err)
	require.Nil(t, info, "info must be nil on error to prevent caller misuse")
	require.ErrorIs(t, err, idErr, "backend error must be exposed via errors.Is")
}

// TestGetSelfEnclaveInfo_TDXShapeProjection documents the legacy-shape
// projection for a TDX Identity. The shim populates UniqueID with the full
// 240-byte CodeCommitment, breaking the 32-byte SGX assumption that some
// callers may still encode. This test ensures any future change to the
// projection logic forces a deliberate update of this assertion.
func TestGetSelfEnclaveInfo_TDXShapeProjection(t *testing.T) {
	tdxCommit := bytes.Repeat([]byte{0xCC}, 240)
	fake := fakeBackend{
		name: "fake-tdx",
		identity: &enclave.Identity{
			Type:           enclave.IdentityTDX,
			CodeCommitment: tdxCommit,
			MRTD:           bytes.Repeat([]byte{0x11}, 48),
		},
	}
	restore := enclave.SwapDefault(fake)
	defer restore()

	info, err := enclave.GetSelfEnclaveInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, 240, len(info.UniqueID),
		"GetSelfEnclaveInfo projects a TDX Identity by copying the 240B CodeCommitment "+
			"into the legacy SGX-shaped UniqueID. Callers expecting a 32B MRENCLAVE will "+
			"reject this; new callers should use TEE.GetSelfIdentity directly.")
	require.Equal(t, tdxCommit, info.UniqueID)
}

// =============================================================================
// Test helpers
// =============================================================================

// dirEntryExists returns (exists, statFailed). statFailed is true only on
// stat errors other than ENOENT.
func dirEntryExists(path string) (exists, statFailed bool) {
	_, err := os.Stat(path)
	if err == nil {
		return true, false
	}
	if os.IsNotExist(err) {
		return false, false
	}
	return false, true
}

// writeFileForTest is a thin os.WriteFile wrapper used by the shim tests.
func writeFileForTest(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
