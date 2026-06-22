package sgx

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// TestSGX_UnsealFromFile_MissingFile exercises the file-read step of
// enclave.UnsealFromFile, which runs before any sealing primitive is
// invoked. A missing file must surface as a wrapped read error rather than
// a confusing seal-layer error. This test runs on any host because it never
// reaches the ego/ecrypto unseal call.
func TestSGX_UnsealFromFile_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := enclave.UnsealFromFile(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to read")
}
