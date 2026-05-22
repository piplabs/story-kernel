//go:build !sgx && !tdx

package cmd

// Blank-import the noop backend so its init() registers it as the active TEE
// backend. This file is the build-tag selector for untagged (dev) builds.
// The companion files cmd/tee_sgx.go and cmd/tee_tdx.go import the production
// backends under -tags sgx and -tags tdx respectively; the build tags above
// guarantee mutual exclusion.
import _ "github.com/piplabs/story-kernel/enclave/noop"
