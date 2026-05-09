//go:build tdx && !sgx

package cmd

// Blank-import the TDX backend so its init() registers it as the active TEE
// backend. This file is the build-tag selector for production TDX builds.
//
// See cmd/tee_sgx.go for the mutual-exclusion rationale; the same applies
// here. Do not widen this tag to plain `tdx` — that would silently allow
// `-tags "sgx tdx"` to compile both registrar files, with the second
// enclave.Register call panicking at runtime instead of failing closed at
// compile time.
import _ "github.com/piplabs/story-kernel/enclave/tdx"
