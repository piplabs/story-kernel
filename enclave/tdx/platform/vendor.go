package platform

import (
	"fmt"
	"sync"
)

// QuoteProvider produces TDX attestation quotes. It is intentionally
// structurally identical to enclave/tdx.QuoteProvider so that values
// satisfying this interface also satisfy the parent package's interface
// without an explicit conversion. Duplicating the declaration here avoids
// an enclave/tdx -> platform -> enclave/tdx import cycle: vendor
// sub-packages embed platform but must never depend on enclave/tdx.
//
// Keep the method set EXACTLY in sync with enclave/tdx.QuoteProvider. If
// the parent interface gains a method, this one must gain the same
// method on the same call. A linter or interface-conformance test in
// enclave/tdx is the recommended guard against drift; see the
// vendorSatisfiesParent assertion in enclave/tdx/quote.go.
type QuoteProvider interface {
	// GetQuote returns a TDX V4/V5 quote that embeds reportData (<= 64
	// bytes, padded to 64 bytes with zeros). The returned slice is the
	// raw quote bytes suitable for on-chain submission to the TDX
	// validation hook.
	GetQuote(reportData []byte) ([]byte, error)
}

// Vendor is a TDX quote-acquisition adapter for a specific deployment
// environment (configfs-tsm direct on bare-metal / GCP / IBM, ...).
//
// Each vendor adapter knows ONE way to acquire a raw TDX V4/V5 quote.
// Vendor adapters are stateless after construction; the parent package
// caches the chosen vendor's QuoteProvider for the process lifetime.
type Vendor interface {
	// Name is a stable short identifier matching the package name and
	// STORY_TDX_VENDOR override value (currently only "direct").
	// Names must be lowercase ASCII without whitespace; the registry
	// does not normalize.
	Name() string

	// Probe returns nil if this vendor's attestation interface is
	// reachable on the current host. A non-nil error indicates the
	// vendor is not applicable; callers iterate to the next one. Must
	// NOT have side effects beyond cheap reads (no allocation of NV
	// indexes, no HTTP requests with credentials, etc.).
	Probe() error

	// QuoteProvider returns a fully constructed QuoteProvider. Called
	// once after Probe() succeeds. May allocate resources; the caller
	// takes ownership. Errors here are NOT a signal to fall through to
	// the next vendor — the caller treats them as a hard failure
	// because Probe() already succeeded.
	QuoteProvider() (QuoteProvider, error)
}

// registry holds all Vendors registered via Register. It is populated
// from sub-package init() functions during program startup; reads after
// init are unlocked because the map is never written after init returns
// in any well-formed binary. The mutex guards Register itself so
// concurrent init() calls (Go does not technically guarantee this never
// happens) are safe.
var (
	registryMu sync.Mutex
	registry   = map[string]Vendor{}
	order      []string // preserves registration order for Order()
)

// Register installs v in the global vendor registry under v.Name().
// Duplicate registration panics — vendor name collision is a build
// misconfiguration that must fail loudly at process startup, not be
// silently accepted with last-write-wins semantics.
//
// Register is intended to be called from vendor sub-package init()
// functions only. Calling it from main-line code is supported but not
// idiomatic.
func Register(v Vendor) {
	if v == nil {
		panic("platform.Register: nil vendor")
	}
	name := v.Name()
	if name == "" {
		panic("platform.Register: vendor with empty Name()")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("platform.Register: vendor %q already registered", name))
	}
	registry[name] = v
	order = append(order, name)
}

// Lookup returns the vendor registered under name, or nil if no vendor
// with that name has been registered. The returned Vendor must be
// treated as immutable; callers MUST NOT modify any fields exposed by
// concrete vendor types (the registry returns the same value to every
// caller).
func Lookup(name string) Vendor {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[name]
}

// Order returns vendors in registration order. The slice is freshly
// allocated on every call so callers can mutate it without affecting
// the registry. This list defines auto-detect probe priority: the
// first vendor whose Probe() succeeds wins.
func Order() []Vendor {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Vendor, len(order))
	for i, name := range order {
		out[i] = registry[name]
	}
	return out
}

// Names returns the registered vendor names in registration order. It
// is provided for diagnostic use (e.g., the error message when an
// override does not match any registered vendor).
func Names() []string {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]string, len(order))
	copy(out, order)
	return out
}
