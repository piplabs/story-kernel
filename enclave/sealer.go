package enclave

// Sealer encrypts and decrypts data under a TEE-bound sealing key.
//
// Implementations must guarantee that ciphertext produced by Seal can only be
// recovered by Unseal running inside the same TEE identity. SGX binds the
// sealing key to MRENCLAVE; TDX binds it to a TPM PolicyOR over a configured
// set of MRTD/RTMR-derived PCR digests.
//
// Concurrency: Seal and Unseal MUST be safe for concurrent use. Sub-package
// implementations that wrap a non-reentrant primitive (e.g. /dev/tpm0) take
// their own per-instance lock; the sealdb wrapper relies on this contract and
// does not synchronize Sealer calls itself.
type Sealer interface {
	// Seal returns a TEE-identity-bound ciphertext that can be persisted at
	// rest. The output is opaque to callers.
	Seal(plaintext []byte) ([]byte, error)
	// Unseal reverses Seal. It MUST fail if the running TEE identity differs
	// from the identity that produced the sealed blob.
	Unseal(sealed []byte) ([]byte, error)
}
