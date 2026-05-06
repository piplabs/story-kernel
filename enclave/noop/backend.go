// Package noop provides the fail-closed default TEE backend.
//
// noop is registered as the active backend when neither the sgx nor the tdx
// build tag is set, via cmd/tee_noop.go's blank import. Every TEE operation
// returns enclave.ErrNoTEE so that accidental use in production fails loudly
// rather than silently producing unsealed key material.
package noop

import (
	cmtdb "github.com/cometbft/cometbft-db"
	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave"
)

// Backend is the fail-closed dev-only TEE backend. Construct via the blank
// import in cmd/tee_noop.go; production code never references this type
// directly.
type Backend struct{}

// Compile-time assertion that Backend satisfies enclave.TEE. The (*Backend)(nil)
// form is used consistently across all backend sub-packages (sgx, tdx, noop).
// See enclave/sgx/backend.go for the rationale.
var _ enclave.TEE = (*Backend)(nil)

func init() {
	enclave.Register(Backend{})
	log.Warn("enclave: noop backend active — TEE operations will fail-closed. " +
		"Build with -tags sgx (production) or -tags tdx for a real TEE.")
}

// Backend returns the short backend identifier "noop" for logs and metrics.
func (Backend) Backend() string { return "noop" }

func (Backend) GetRemoteQuote([]byte) ([]byte, error) {
	return nil, enclave.ErrNoTEE
}

func (Backend) GetSelfIdentity() (*enclave.Identity, error) {
	return nil, enclave.ErrNoTEE
}

func (Backend) GetSelfCodeCommitment() ([]byte, error) {
	return nil, enclave.ErrNoTEE
}

func (Backend) ValidateCodeCommitment([]byte) error {
	return enclave.ErrNoTEE
}

func (Backend) Seal([]byte) ([]byte, error) {
	return nil, enclave.ErrNoTEE
}

func (Backend) Unseal([]byte) ([]byte, error) {
	return nil, enclave.ErrNoTEE
}

func (Backend) NewSealedDB(string, string) (cmtdb.DB, error) {
	return nil, enclave.ErrNoTEE
}
