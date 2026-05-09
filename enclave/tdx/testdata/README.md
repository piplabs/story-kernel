# Test data

## tdx_prod_quote_SPR_E4.dat

A production-shape Intel TDX (DCAP V4) quote captured on a Sapphire Rapids
host. Used to exercise `parseTDXQuoteV4`'s success path through
`abi.QuoteToProto`, which requires the full DCAP envelope (header + body +
signed data + cert chain) and rejects the slimmer synthetic quotes the
unit-test helpers generate.

**Source**: `github.com/google/go-tdx-guest@v0.3.2-0.20250814004405-ffb0869e6f4d/testing/testdata/tdx_prod_quote_SPR_E4.dat`

**License**: Apache License 2.0 (same as the upstream `go-tdx-guest`
repository).
