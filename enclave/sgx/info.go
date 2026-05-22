package sgx

import (
	"github.com/piplabs/story-kernel/enclave"
)

// GetSelfEnclaveInfo returns the legacy SGX-shaped self-info for the running
// enclave. Internally it queries the active backend's GetSelfIdentity and
// projects the SGX-relevant fields.
//
// Deprecated: Prefer enclave.GetSelfCodeCommitment / enclave.Default().GetSelfIdentity
// directly; this shim is kept for SGX-internal tests and legacy callers.
func GetSelfEnclaveInfo() (*EnclaveInfo, error) {
	id, err := enclave.Default().GetSelfIdentity()
	if err != nil {
		return nil, err
	}

	return &EnclaveInfo{
		ProductID: id.ProductID,
		UniqueID:  id.CodeCommitment,
	}, nil
}
