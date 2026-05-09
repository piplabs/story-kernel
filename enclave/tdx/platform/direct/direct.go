package direct

import (
	"errors"
	"fmt"

	tdxclient "github.com/google/go-tdx-guest/client"

	"github.com/piplabs/story-kernel/enclave/tdx/platform"
)

// VendorName is the stable identifier for this vendor. It must match the
// package name and the value the operator passes via STORY_TDX_VENDOR to
// force this adapter at startup.
const VendorName = "direct"

// ErrNoTDXDevice is the package-private sentinel for "no TDX guest
// interface reachable on this host" inside the direct adapter. It is
// DISTINCT from enclave/tdx.ErrNoTDXDevice — same message text, but a
// different *errors.errorString pointer — to avoid an import cycle
// (tdx -> platform/direct -> tdx). errors.Is matches by pointer
// identity for sentinel errors, so direct.ErrNoTDXDevice and
// tdx.ErrNoTDXDevice do NOT match each other directly.
//
// Callers detecting "no TDX device" generically should match against
// tdx.ErrNoTDXDevice, NOT this sentinel. The parent package's
// selectVendor wraps probe failures from any vendor with
// tdx.ErrNoTDXDevice via fmt.Errorf("...%w: %w...", tdx.ErrNoTDXDevice,
// vendorErr), so errors.Is(err, tdx.ErrNoTDXDevice) holds at every
// caller regardless of which vendor's probe failed.
//
// In-package callers (Probe, QuoteProvider in this file) use this
// local sentinel directly as the wrap target; that keeps the wrap
// chain self-contained and lets unit tests inside this package match
// against the local pointer without re-importing the parent.
var ErrNoTDXDevice = errors.New("tdx: no TDX device available (configfs-tsm)")

// tdxReportDataSize is the maximum size of user data embedded in a TDX
// quote. The TDX architecture pads shorter inputs with zeros to fill
// exactly 64 bytes. Mirrored from enclave/tdx for the same reason as
// ErrNoTDXDevice (avoid import cycle).
const tdxReportDataSize = 64

// Vendor is exported for compile-time interface satisfaction in tests
// outside this package. Production code never references it directly;
// init() registers the singleton.
type Vendor struct{}

// Compile-time assertion that direct.Vendor satisfies platform.Vendor.
var _ platform.Vendor = (*Vendor)(nil)

// getQuoteProvider is the seam through which Probe and QuoteProvider
// reach go-tdx-guest. The default delegates to
// tdxclient.GetQuoteProvider; tests in this package may swap it (with
// a deferred restore) to exercise the IsSupported failure branch
// without TDX silicon. The seam is package-private so it cannot be
// touched from outside this file.
//
// The return type is the interface tdxclient.QuoteProvider rather
// than the concrete *LinuxConfigFsQuoteProvider that the upstream
// returns; this makes the seam compatible with test stubs that do
// not embed the upstream's concrete type. The runtime cost is one
// implicit interface conversion per init.
//
// We deliberately do NOT use a constructor argument or interface
// injection on Vendor itself — the Vendor methods are part of the
// platform.Vendor contract whose signatures are fixed. A package-
// level seam is the minimum-surface alternative.
var getQuoteProvider = func() (tdxclient.QuoteProvider, error) {
	return tdxclient.GetQuoteProvider()
}

// Name returns VendorName.
func (Vendor) Name() string { return VendorName }

// Probe checks that the configfs-tsm interface is reachable on the
// running host. Behavior is byte-identical to the pre-refactor
// newLinuxQuoteProvider's discovery sequence:
//
//  1. tdxclient.GetQuoteProvider() — returns the configfs-tsm provider
//     (no /dev/tdx_guest fallback in upstream go-tdx-guest).
//  2. provider.IsSupported() — confirms the underlying interface is
//     usable (configfs-tsm enabled, kernel >= 6.7).
//
// Either failure is wrapped in ErrNoTDXDevice so callers using
// errors.Is(err, ErrNoTDXDevice) detect the condition without parsing
// vendor-internal error strings.
//
// This call is cheap: no NV index allocation, no HTTP request, no
// kernel ioctl beyond the one configfs-tsm path resolution that
// IsSupported performs internally. Safe to call from a per-process
// init path.
func (Vendor) Probe() error {
	qp, err := getQuoteProvider()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoTDXDevice, err)
	}
	if err := qp.IsSupported(); err != nil {
		return fmt.Errorf("%w: %w", ErrNoTDXDevice, err)
	}
	return nil
}

// QuoteProvider constructs a fresh QuoteProvider bound to the host's
// configfs-tsm interface. It re-runs the same discovery as Probe()
// rather than caching; the cost is one path resolution and the
// vendor struct stays trivially stateless and goroutine-safe.
//
// The direct vendor produces raw V4 quotes — the TDX-side equivalent
// of the SGX backend's report_data semantics: the caller's user_data
// is padded to 64 bytes and embedded into V4.report_data; the hardware
// (configfs-tsm) signs. There is no AK provisioning, no TPM2_Quote, no
// Path-B bundle assembly here. The paravisor vendor remains the only
// path that emits Path-B bundles, because on a paravisor-mediated
// guest V4.report_data is paravisor-locked to SHA256(VariableData) and
// the user_data must be bound via TPMS_ATTEST.qualifyingData instead.
//
// Errors here are NOT a signal to fall through to the next vendor.
// QuoteProvider is called only after Probe() has succeeded, so an
// error here is a hard failure (transient TPM/driver glitch between
// probe and provider construction); the parent surfaces it directly.
func (Vendor) QuoteProvider() (platform.QuoteProvider, error) {
	qp, err := getQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoTDXDevice, err)
	}
	if err := qp.IsSupported(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoTDXDevice, err)
	}
	return &linuxQuoteProvider{provider: qp}, nil
}

// linuxQuoteProvider is the production QuoteProvider for the direct
// adapter. The actual selection of the underlying interface is
// performed by go-tdx-guest internally; we never duplicate that
// detection here.
//
// linuxQuoteProvider is stateless beyond the embedded tdxclient
// provider, mirroring the SGX backend's provider shape. There is
// nothing to lock, nothing to cache; concurrent GetQuote callers are
// safe by construction.
type linuxQuoteProvider struct {
	provider tdxclient.QuoteProvider
}

// GetQuote pads the caller's reportData to 64 bytes and asks the
// hardware (via configfs-tsm) to produce a raw V4 quote whose
// V4.report_data equals the padded buffer. This is byte-equivalent to
// the SGX backend's GetRemoteQuote contract on the report_data axis;
// the on-chain TDX validation hook compares the leading 32 bytes of
// V4.report_data against the expected keccak256(EnclaveInstanceData)
// commitment.
//
// The padded buffer is a value type ([64]byte) so go-tdx-guest's
// dispatcher can route it without allocation. We do NOT zero an
// intermediate slice on return: the padded buffer holds public,
// non-secret commitment bytes (keccak256 of public ED25519 + secp256k1
// pub keys). Treating it as memory-hygiene-sensitive would be
// over-engineering.
func (l *linuxQuoteProvider) GetQuote(reportData []byte) ([]byte, error) {
	if len(reportData) > tdxReportDataSize {
		return nil, fmt.Errorf("tdx: reportData exceeds %d bytes: got %d", tdxReportDataSize, len(reportData))
	}

	var padded [tdxReportDataSize]byte
	copy(padded[:], reportData)

	quote, err := tdxclient.GetRawQuote(l.provider, padded)
	if err != nil {
		return nil, fmt.Errorf("tdx: GetRawQuote: %w", err)
	}
	return quote, nil
}

// init registers the direct adapter with the platform registry. Called
// automatically when this package is imported (via the blank import in
// enclave/tdx/backend.go). Direct registers first so it wins on every
// host where configfs-tsm works, matching the pre-refactor behavior
// where it was the only path.
func init() {
	platform.Register(Vendor{})
}
