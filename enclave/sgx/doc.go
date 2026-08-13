// Package sgx implements the production TEE backend for Intel SGX enclaves
// running under the Gramine LibOS.
//
// The package registers itself as the active enclave.TEE backend via init()
// when this package is imported. The build-tag selector is cmd/tee_sgx.go's
// blank import under -tags sgx; the package itself carries no build-tag
// directives so its source is available to tooling regardless of build mode.
//
// Methods are split across:
//   - quote.go    GetRemoteQuote, GetSelfCodeCommitment, ValidateCodeCommitment
//     via the Gramine /dev/attestation pseudo-filesystem.
//   - seal.go     Seal/Unseal backed by ego/ecrypto's MRENCLAVE-derived key.
//   - sealdb.go   NewSealedDB delegates to enclave/sealdb with the
//     Gramine-aware noflock storage opener.
//   - noflock.go  noFlockStorage + OpenFileNoFlock — Gramine ENOSYS-on-flock
//     workaround.
package sgx
