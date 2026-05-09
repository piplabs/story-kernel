// Package tdx implements the production TEE backend for Intel TDX trust
// domains running under a Linux paravisor or in-TD swtpm.
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
//     IBM TDX hosts. Additional vendor adapters (e.g., paravisor-mediated
//     guests) register themselves into the same registry. Operator
//     override via STORY_TDX_VENDOR=<name>.
//   - Identity is the native concatenation MRTD || RTMR0..3 (240 bytes).
//   - Sealing uses a TPM2 PolicyOR over per-provider PCR sets
//     (supportedProviders) combined with a hybrid AES-GCM wrap. The TPM
//     seals only an AES-256 data-encryption key; the payload is encrypted
//     by the wrap so TPM throughput does not bottleneck large values.
//   - vTPM-in-TCB assumption: the vTPM must be inside the TD's TCB
//     (paravisor or in-TD swtpm). A host-provided vTPM is NOT acceptable
//     for sealing because PCR extension in such a setup is not bound to
//     the TD's identity.
//
// Methods are split across:
//   - backend.go         Backend struct + init() registration + Identifier methods.
//   - quote.go           QuoteProvider interface, selectVendor, failClosedQuoteProvider.
//   - identity.go        Quote parser (V4/V5), cloneSlice/cloneIdentity helpers.
//   - providers.go       ProviderPolicy + supportedProviders registry.
//   - seal.go            TPM2 PolicyOR sealing, hybrid wrap, TXS1 wire format.
//   - selfcheck.go       Startup self-check + bootstrap WARN.
//   - sealdb.go          NewSealedDB delegates to enclave/sealdb.
//   - platform/          Vendor plugin registry (Vendor interface).
//   - platform/direct/   configfs-tsm vendor adapter.
//   - platform/paravisor/ paravisor-mediated guest adapter (OpenHCL).
package tdx
