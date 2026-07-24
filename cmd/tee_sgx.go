//go:build sgx && !tdx

package cmd

// Blank-import the SGX backend so its init() registers it as the active TEE
// backend. This file is the build-tag selector for production SGX builds.
//
// IMPORTANT — mutual exclusion at compile time:
// The build tag `sgx && !tdx` makes this file mutually exclusive with
// cmd/tee_tdx.go (`tdx && !sgx`) and cmd/tee_noop.go (`!sgx && !tdx`). A
// misconfigured build that passes both `-tags sgx tdx` matches NONE of
// these files: the cmd package then has no TEE registrar, and the first
// enclave.Default() call panics with the diagnostic in enclave/tee.go.
// This is the desired fail-closed posture — a dual-backend binary is
// nonsensical and we want the failure to be loud at first use.
//
// Do not widen this tag to plain `sgx` — that would silently allow
// `-tags "sgx tdx"` to compile both registrar files, with the second
// enclave.Register call panicking at runtime instead of failing closed.
import _ "github.com/piplabs/story-kernel/enclave/sgx"
