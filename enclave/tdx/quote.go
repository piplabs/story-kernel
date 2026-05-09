package tdx

import (
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// QuoteProvider produces TDX attestation quotes. Production code uses a
// vendor-specific provider selected at runtime by selectVendor; tests
// inject mockQuoteProvider so the kernel package compiles and exercises
// code paths on hosts without TDX silicon.
//
// The interface is intentionally structurally identical to
// platform.QuoteProvider so vendor adapters' constructed providers
// satisfy this interface implicitly. If the method set changes, update
// platform.QuoteProvider in lockstep — see the compile-time assertion
// platformQuoteProviderSatisfies below.
type QuoteProvider interface {
	// GetQuote returns a TDX V4/V5 quote that embeds reportData (<= 64 bytes,
	// padded to 64 bytes with zeros). The returned slice is the raw quote
	// bytes suitable for on-chain submission to the TDX validation hook.
	GetQuote(reportData []byte) ([]byte, error)
}

// platformQuoteProviderSatisfies is a compile-time assertion that any
// platform.QuoteProvider value also satisfies tdx.QuoteProvider. If the
// two interfaces ever diverge, this declaration fails to compile and
// the discrepancy is caught at build time rather than at first quote
// call. The variable name is intentionally descriptive; it does not
// participate in linking.
var _ QuoteProvider = (platform.QuoteProvider)(nil)

// tdxQuoteProviderSatisfiesPlatform is the reverse-direction
// compile-time assertion: any tdx.QuoteProvider value must also
// satisfy platform.QuoteProvider. The forward assertion above only
// catches "platform interface gained a method that tdx lacks"; this
// reverse assertion also catches "tdx interface gained a method that
// platform lacks." Together the two pin the interfaces against silent
// drift in either direction.
//
// Co-locating both assertions in this parent package avoids an import
// cycle: vendor sub-packages such as enclave/tdx/platform/direct
// cannot import enclave/tdx (cycle: tdx -> platform/direct -> tdx via
// the blank import in backend.go), so the reverse assertion lives
// here rather than in any vendor adapter.
var _ platform.QuoteProvider = (QuoteProvider)(nil)

// ErrNoTDXDevice is returned (wrapped via %w) from any TDX operation when
// the host has no usable TDX attestation interface (configfs-tsm
// unavailable, kernel < 6.7, or hardware lacking TDX). Callers can detect
// the condition with errors.Is(err, tdx.ErrNoTDXDevice) regardless of how
// many wrap layers the runtime adds.
//
// Cross-package guarantee: vendor sub-packages (e.g.,
// enclave/tdx/platform/direct) MAY define their own package-private
// "no device" sentinel (with the same message text) to avoid an import
// cycle. selectVendor in this package wraps probe failures from any
// vendor with this sentinel — so callers using
// errors.Is(err, tdx.ErrNoTDXDevice) detect the condition uniformly,
// regardless of which vendor adapter probed and failed.
var ErrNoTDXDevice = errors.New("tdx: no TDX device available (configfs-tsm)")

// tdxReportDataSize is the maximum size of user data embedded in a TDX quote.
// The TDX architecture pads shorter inputs with zeros to fill exactly 64
// bytes.
const tdxReportDataSize = 64

// selectVendor walks the platform vendor registry and returns a
// QuoteProvider for the first vendor whose Probe() succeeds. The
// override argument honors the STORY_TDX_VENDOR env var read by the
// caller (backend.go's init).
//
// Selection rules:
//
//  1. If override is non-empty, only that vendor is attempted. If the
//     name is not registered, return an error listing available
//     vendors. If the named vendor's Probe() fails, return an error
//     wrapping BOTH ErrNoTDXDevice AND the underlying probe error
//     WITHOUT falling through to other vendors — the operator's
//     explicit override is honored strictly. Wrapping ErrNoTDXDevice
//     here guarantees callers using errors.Is(err, ErrNoTDXDevice)
//     detect "no device" uniformly regardless of which vendor's probe
//     failed (vendor sub-packages may have their own package-private
//     sentinel to avoid an import cycle; this package's sentinel is
//     the canonical one for callers).
//  2. If override is empty, iterate platform.Order() and pick the
//     first vendor whose Probe() returns nil. Probe failures from
//     other vendors are logged at DEBUG only — they are an expected
//     part of the auto-detect flow.
//  3. If no vendor probes successfully, return an error wrapped in
//     ErrNoTDXDevice so callers using errors.Is(..., ErrNoTDXDevice)
//     keep working. The backend's init() turns this into a
//     failClosedQuoteProvider as before.
//
// The chosen vendor's QuoteProvider() is called once; the returned
// provider is bound to the process lifetime and shared across all
// concurrent goroutines. QuoteProvider construction errors are NOT a
// signal to fall through (Probe already succeeded), so they propagate
// directly.
func selectVendor(override string) (QuoteProvider, error) {
	if override != "" {
		v := platform.Lookup(override)
		if v == nil {
			return nil, fmt.Errorf("tdx: STORY_TDX_VENDOR=%q not registered (available: %v)",
				override, platform.Names())
		}
		if err := v.Probe(); err != nil {
			// Wrap BOTH ErrNoTDXDevice AND the underlying probe error
			// (Go 1.20+ %w: %w form). errors.Is walks the entire
			// chain, so callers that match against tdx.ErrNoTDXDevice
			// detect this case uniformly even when the underlying
			// vendor wrapped its own package-private sentinel (e.g.,
			// direct.ErrNoTDXDevice has the same message text but a
			// different pointer to avoid an import cycle).
			return nil, fmt.Errorf("tdx: forced vendor %q probe failed: %w: %w",
				override, ErrNoTDXDevice, err)
		}
		qp, err := v.QuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("tdx: forced vendor %q construct: %w", override, err)
		}
		log.Infof("tdx: using forced vendor adapter %q", override)
		return qp, nil
	}

	for _, v := range platform.Order() {
		if err := v.Probe(); err != nil {
			log.Debugf("tdx: vendor %q probe skipped: %v", v.Name(), err)
			continue
		}
		qp, err := v.QuoteProvider()
		if err != nil {
			// Probe succeeded but constructor failed. Surface this as
			// a hard error rather than silently trying the next
			// vendor — Probe is supposed to be the cheap predicate
			// that says "yes I work here."
			return nil, fmt.Errorf("tdx: vendor %q construct: %w", v.Name(), err)
		}
		log.Infof("tdx: using vendor adapter %q", v.Name())
		return qp, nil
	}
	// All vendor probes failed. Wrap ErrNoTDXDevice so callers using
	// errors.Is(..., ErrNoTDXDevice) detect "no TDX device" uniformly,
	// matching the override-path probe-failure behavior above.
	return nil, fmt.Errorf("%w: no vendor adapter probe succeeded (available: %v)",
		ErrNoTDXDevice, platform.Names())
}

// failClosedQuoteProvider is registered by the backend's init when no
// vendor adapter probes successfully on the host. Every method returns
// the wrapped initialization error so that the binary fails loudly on
// any attempt to produce a quote, rather than silently returning empty
// bytes that could be mistaken for a successful attestation.
type failClosedQuoteProvider struct {
	err error
}

// GetQuote always returns the wrapped initialization error.
func (f failClosedQuoteProvider) GetQuote([]byte) ([]byte, error) {
	return nil, fmt.Errorf("tdx: quote provider unavailable: %w", f.err)
}
