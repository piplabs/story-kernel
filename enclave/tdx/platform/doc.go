// Package platform exposes a vendor plugin abstraction for TDX quote
// acquisition. Each vendor sub-package (direct, paravisor, gcp, ibm, ...)
// implements one Vendor and registers itself in this package's global
// registry from its init() function.
//
// The parent package (enclave/tdx) consumes the registry through three
// public hooks:
//
//   - platform.Lookup(name)  — by-name resolution for the
//     STORY_TDX_VENDOR override.
//   - platform.Order()       — registration-ordered iteration for
//     auto-detect probing.
//   - platform.Register(v)   — additive registration; called from
//     vendor sub-packages' init().
//
// Selection algorithm (in enclave/tdx/quote.go):
//
//  1. If STORY_TDX_VENDOR is set, Lookup that name and use it (or fail
//     if not registered).
//  2. Otherwise iterate Order(); the first vendor whose Probe() returns
//     nil wins.
//  3. If no vendor probes successfully, fall back to a fail-closed
//     QuoteProvider that returns the wrapped initialization error from
//     every method call.
//
// Adding a new vendor:
//
//  1. Create enclave/tdx/platform/<name>/<name>.go.
//  2. Implement the Vendor interface on a package-private struct.
//  3. Call platform.Register(<vendorStruct>{}) in package init().
//  4. Add a blank import for the new package in enclave/tdx/backend.go
//     so the init() registration runs at backend startup.
//
// Probe semantics:
//
//   - Probes MUST be cheap. No HTTP requests with credentials, no NV
//     index allocation, no key generation. Allowed: stat'ing a /sys
//     path, reading a fixed-size header from a vTPM NV index, opening
//     /dev/tpmrm0 read-only.
//   - Probe failure is an expected condition: a vendor that is not
//     applicable on the current host returns a non-nil error so the
//     caller iterates to the next one. Probe SHOULD NOT log at WARN or
//     above; the caller logs the chosen vendor at INFO.
//   - Probes MUST be idempotent and goroutine-safe; the registry is
//     mutex-protected but vendor structs are values shared across calls.
//
// Build-tag layering:
//
// Build tags continue to gate the TEE backend (sgx | tdx | noop) at the
// cmd/ level. Within a tdx build, ALL registered vendor adapters are
// compiled in; vendor selection is purely a runtime decision. One
// `make build-tdx` artifact runs on every TDX vendor whose adapter is
// linked. This is by design — the TCB cost of additional vendor source
// code is negligible compared to the paravisor + TDX module + Linux
// kernel that dominates the TCB measurement.
package platform
