package sgx

import (
	"github.com/piplabs/story-kernel/enclave"
)

// Backend is the production TEE backend running inside an Intel SGX enclave
// under the Gramine LibOS. The empty struct carries no state; per-process
// state (e.g., the cached self-identity sync.Once) is at file scope inside
// this package.
type Backend struct{}

// Compile-time assertion that Backend satisfies enclave.TEE. The (*Backend)(nil)
// form is used consistently across all backend sub-packages (sgx, tdx, noop).
// It works for both value-receiver methods (SGX/noop, no struct state) and
// pointer-receiver methods (TDX, mutable struct state) because *T's method
// set includes both value- and pointer-receiver methods.
var _ enclave.TEE = (*Backend)(nil)

func init() {
	enclave.Register(Backend{})
}

// Backend returns the short identifier "sgx" for logs and metrics.
func (Backend) Backend() string { return "sgx" }
