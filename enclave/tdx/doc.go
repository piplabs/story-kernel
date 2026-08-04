// Package tdx implements the production TEE backend for Intel TDX trust
// domains exposing the upstream Linux configfs-tsm guest interface, with
// the vTPM provided by an in-TD swtpm.
//
// The package registers itself as the active enclave.TEE backend via init()
// when this package is imported. The build-tag selector is cmd/tee_tdx.go's
// blank import under -tags tdx; the package itself carries no build-tag
// directives so its source is available to tooling regardless of build mode.
//
// Architecture:
//
//   - Quotes are produced via a vendor plugin selected at runtime from
//     enclave/tdx/platform/. The default registered adapter is "direct"
//     (configfs-tsm on kernel >= 6.7) which serves bare-metal, GCP and
//     IBM TDX hosts. Vendor selection is automatic; no setup is required.
//     STORY_TDX_VENDOR=<name> is an optional operator escape hatch to force
//     a specific adapter.
//   - Paravisor-mediated TDX guests (e.g., Azure Confidential VM TDX with
//     OpenHCL) are intentionally out of scope.
//   - CodeCommitment is the v3 binary commitment keccak256(RTMR3)
//     (32 bytes). RTMR3 is bound to *this* Go binary by a one-shot
//     extend during init() with SHA-384(/proc/self/exe), so the value
//     equals SHA384(0x00…00 || SHA384(elf)) and is reflected in every
//     subsequent quote. RTMR2 measures only TD initrd + cmdline (not
//     the Go binary) and so has moved into the platform commitment
//     (computed chain-side as keccak256(MRTD || RTMR0 || RTMR1 ||
//     RTMR2)). Identity still exposes MRTD/RTMR0..3 as raw 48-byte
//     measurements for diagnostics.
//   - Sealing uses a TPM2 PolicyOR over per-provider PCR sets
//     (supportedProviders) combined with a hybrid AES-GCM wrap. The TPM
//     seals only an AES-256 data-encryption key; the payload is encrypted
//     by the wrap so TPM throughput does not bottleneck large values.
//   - vTPM-in-TCB assumption: the vTPM must be inside the TD's TCB (an
//     in-TD swtpm). A host-provided vTPM is NOT acceptable for sealing
//     because PCR extension in such a setup is not bound to the TD's
//     identity.
//
// Methods are split across:
//   - backend.go         Backend struct + init() registration + Identifier methods.
//   - quote.go           QuoteProvider interface, selectVendor, failClosedQuoteProvider.
//   - identity.go        Quote parser (V4/V5), cloneSlice helper.
//   - providers.go       ProviderPolicy + supportedProviders registry.
//   - seal.go            TPM2 PolicyOR sealing, hybrid wrap, TXS1 wire format.
//   - selfcheck.go       Startup self-check + bootstrap WARN.
//   - sealdb.go          NewSealedDB delegates to enclave/sealdb.
//   - platform/          Vendor plugin registry (Vendor interface).
//   - platform/direct/   configfs-tsm vendor adapter.
package tdx
