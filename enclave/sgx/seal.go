package sgx

import (
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
)

// Seal encrypts plaintext using the SGX unique key (MRENCLAVE-derived).
func (Backend) Seal(plaintext []byte) ([]byte, error) {
	sealed, err := ecrypto.SealWithUniqueKey(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to seal the data: %w", err)
	}

	return sealed, nil
}

// Unseal decrypts data sealed by SealWithUniqueKey under the running enclave.
func (Backend) Unseal(sealed []byte) ([]byte, error) {
	plaintext, err := ecrypto.Unseal(sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal oracle key: %w", err)
	}

	return plaintext, nil
}
