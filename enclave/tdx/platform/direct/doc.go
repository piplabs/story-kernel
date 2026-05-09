// Package direct implements the configfs-tsm TDX vendor adapter.
//
// "Direct" refers to the upstream Linux TDX guest path that exposes the
// TDX module's quote interface via configfs-tsm
// (/sys/kernel/config/tsm/report/) on kernel >= 6.7. This is the
// path used on bare-metal TDX hosts, GCP confidential VMs, and IBM
// Cloud TDX VMs where the Linux guest is NOT mediated by a paravisor.
//
// Paravisor-mediated TDX guests (running an OpenHCL-class paravisor
// under Hyper-V isolation type 3) take a different code path: the
// upstream Linux driver rejects them with "Invalid offer 3" in dmesg,
// and configfs-tsm returns ENXIO on those hosts. The paravisor adapter
// (enclave/tdx/platform/paravisor) handles that interface and is
// selected at runtime based on Probe() outcome.
//
// Probe semantics:
//
//   - Probe attempts the same go-tdx-guest discovery the production
//     code has always done: tdxclient.GetQuoteProvider() followed by
//     IsSupported(). Both must succeed.
//   - On non-TDX hosts (contributor laptops, macOS dev environments)
//     Probe returns an error wrapping this package's local
//     ErrNoTDXDevice (a distinct sentinel from enclave/tdx.ErrNoTDXDevice
//     — same message text, different pointer, kept package-private to
//     avoid an import cycle). The parent's selectVendor in
//     enclave/tdx then re-wraps the chain with tdx.ErrNoTDXDevice,
//     so callers matching against the parent sentinel detect the
//     condition uniformly. selectVendor falls through to the next
//     registered vendor on probe failure (when no operator override
//     is set) and ultimately registers a failClosedQuoteProvider if
//     no vendor matches.
//   - This vendor registers itself first in init() so it wins on every
//     host where it works, including the existing GCP TDX devnet.
package direct
