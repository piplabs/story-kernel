package sgx

// EnclaveInfo is the legacy SGX-shaped self-info structure preserved for
// callers that consume MRENCLAVE + ISVPRODID directly.
//
// Deprecated: Prefer enclave.Identity via enclave.TEE.GetSelfIdentity. This
// struct is the legacy SGX-shaped projection; new code should accept
// enclave.Identity so TDX-shaped measurements (MRTD/RTMR0..3) are also
// available.
type EnclaveInfo struct {
	ProductID []byte
	UniqueID  []byte
}
