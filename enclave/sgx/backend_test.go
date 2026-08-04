package sgx

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
)

// TestSGX_DefaultBackendName verifies that, with the sgx package imported,
// enclave.Default() returns the registered SGX backend and that its
// Backend() identifier is the canonical short string used in logs and
// metrics.
func TestSGX_DefaultBackendName(t *testing.T) {
	t.Parallel()

	require.Equal(t, "sgx", enclave.Default().Backend())
}
