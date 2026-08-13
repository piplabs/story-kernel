package tdx

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// =============================================================================
// TDX quote layout constants (DCAP V4 + V5).
//
// The DCAP V4 header is 48 bytes for both V4 and V5 quotes. The TDX TEE-type
// discriminator (header.tee_type == 0x00000081, wire bytes [81 00 00 00] LE)
// selects between the SGX and TDX report-body shapes. We parse only the
// measurement fields we need (MRTD + RTMR0..3 + ReportData); the
// signature/cert chain trailing the body is verified chain-side.
//
// CRITICAL OBSERVATION: every measurement field we read sits at the same
// absolute offset in TD10 (V4) and TD15 (V5). The V5 body adds a 16-byte
// trailing TEE_TCB_SVN_2 field that does not affect our offsets. So our
// offset constants are version-independent; only the minimum-quote-size
// length check varies per version.
// =============================================================================

// Quote header layout (versions 4 and 5).
const (
	quoteHeaderSizeTDX = 48

	// Header field offsets.
	quoteOffVersion = 0 // uint16 LE
	quoteOffTeeType = 4 // uint32 LE; TDX = 0x00000081 (wire bytes [81 00 00 00])
)

// TEE-type discriminator inside the quote header.
const (
	teeTypeSGX uint32 = 0x00000000
	// teeTypeTDX is the value of header.tee_type that identifies a TDX
	// quote, matching abi.TeeTDX in google/go-tdx-guest. The wire bytes at
	// offset 4 are [81 00 00 00]; binary.LittleEndian.Uint32 decodes them
	// to 0x00000081. (Confused with 0x81000000 in earlier drafts; that
	// would correspond to wire bytes [00 00 00 81] which is not what real
	// TDX hardware emits.)
	teeTypeTDX uint32 = 0x00000081
)

// TD report body offsets (relative to body start; identical for TD10 and TD15
// for every field we read).
const (
	bodyOffMRTD       = 136
	bodyOffRTMR0      = 328
	bodyOffRTMR1      = 376
	bodyOffRTMR2      = 424
	bodyOffRTMR3      = 472
	bodyOffReportData = 520

	// Field sizes.
	sizeMeasurement = 48 // MRTD, RTMR*, MRSEAM, etc.

	// Body lengths.
	td10BodyLen = 584 // V4
	td15BodyLen = 648 // V5

	// Minimum total quote sizes (header + body), exclusive of the auth_data
	// trailer. The actual quote contains additional signature/cert chain
	// bytes after the body which we do not parse here.
	minQuoteSizeTD10 = quoteHeaderSizeTDX + td10BodyLen // 632
	minQuoteSizeTD15 = quoteHeaderSizeTDX + td15BodyLen // 696
)

// parsedTDXQuote holds the fields we extract from a TDX quote body. Buffers
// are defensive copies so callers cannot mutate the raw quote through them.
type parsedTDXQuote struct {
	Version    uint16
	TeeType    uint32
	MRTD       []byte
	RTMR0      []byte
	RTMR1      []byte
	RTMR2      []byte
	RTMR3      []byte
	ReportData []byte
}

// parseTDXQuote extracts header version, TEE-type discriminator, and the
// measurements we need from a TDX quote. It performs explicit length checks
// at every read so malformed input never causes a panic or out-of-bounds
// read. Used at startup self-check time and for ad-hoc identity extraction.
//
// V4 quotes are parsed via go-tdx-guest's abi.QuoteToProto, which gives us
// the full pb.QuoteV4 struct (header + TDQuoteBody) without us hand-rolling
// byte offsets. V5 (TD15) is not yet supported by go-tdx-guest, so we fall
// back to the manual parser for that path. The manual parser stays self-
// contained for both versions in case operators want a single path that
// does not depend on the upstream library; this is purely an optimization
// to avoid duplicating well-tested upstream code.
func parseTDXQuote(quote []byte) (*parsedTDXQuote, error) {
	if len(quote) < quoteHeaderSizeTDX {
		return nil, fmt.Errorf("tdx: quote too short for header: %d < %d", len(quote), quoteHeaderSizeTDX)
	}

	// Fast V4 path via the upstream parser. Falls through to the manual
	// parser on any error (V5 returns "quote format not supported", and
	// genuine decode errors propagate via the manual parser's diagnostics).
	if v4, err := parseTDXQuoteV4(quote); err == nil {
		return v4, nil
	}

	return parseTDXQuoteManual(quote)
}

// parseTDXQuoteV4 delegates to abi.QuoteToProto for V4 quotes and projects
// the upstream pb.TDQuoteBody fields into our parsedTDXQuote. Returns an
// error for any non-V4 quote or any malformed input; callers fall back to
// parseTDXQuoteManual.
func parseTDXQuoteV4(quote []byte) (*parsedTDXQuote, error) {
	parsed, err := abi.QuoteToProto(quote)
	if err != nil {
		return nil, err
	}
	v4, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("tdx: abi parser returned unexpected type %T", parsed)
	}

	header := v4.GetHeader()
	if header == nil {
		return nil, fmt.Errorf("tdx: V4 quote missing header")
	}
	if got := header.GetTeeType(); got != teeTypeTDX {
		return nil, fmt.Errorf("tdx: not a TDX quote: tee_type=0x%08x", got)
	}

	body := v4.GetTdQuoteBody()
	if body == nil {
		return nil, fmt.Errorf("tdx: V4 quote missing td_quote_body")
	}
	if len(body.MrTd) != sizeMeasurement {
		return nil, fmt.Errorf("tdx: MRTD length %d != %d", len(body.MrTd), sizeMeasurement)
	}
	if len(body.Rtmrs) < 4 {
		return nil, fmt.Errorf("tdx: V4 quote has %d RTMRs (need 4)", len(body.Rtmrs))
	}
	for i, r := range body.Rtmrs[:4] {
		if len(r) != sizeMeasurement {
			return nil, fmt.Errorf("tdx: RTMR%d length %d != %d", i, len(r), sizeMeasurement)
		}
	}
	if len(body.ReportData) != tdxReportDataSize {
		return nil, fmt.Errorf("tdx: ReportData length %d != %d", len(body.ReportData), tdxReportDataSize)
	}

	return &parsedTDXQuote{
		Version:    uint16(header.GetVersion()),
		TeeType:    header.GetTeeType(),
		MRTD:       cloneSlice(body.MrTd),
		RTMR0:      cloneSlice(body.Rtmrs[0]),
		RTMR1:      cloneSlice(body.Rtmrs[1]),
		RTMR2:      cloneSlice(body.Rtmrs[2]),
		RTMR3:      cloneSlice(body.Rtmrs[3]),
		ReportData: cloneSlice(body.ReportData),
	}, nil
}

// parseTDXQuoteManual is the version-agnostic fallback that walks the byte
// layout directly. Used for V5 (TD15) quotes since go-tdx-guest does not
// yet support that format, and as a defensive fallback if the upstream
// parser rejects an otherwise valid quote.
func parseTDXQuoteManual(quote []byte) (*parsedTDXQuote, error) {
	if len(quote) < quoteHeaderSizeTDX {
		return nil, fmt.Errorf("tdx: quote too short for header: %d < %d", len(quote), quoteHeaderSizeTDX)
	}

	version := binary.LittleEndian.Uint16(quote[quoteOffVersion : quoteOffVersion+2])
	teeType := binary.LittleEndian.Uint32(quote[quoteOffTeeType : quoteOffTeeType+4])

	if teeType != teeTypeTDX {
		return nil, fmt.Errorf("tdx: not a TDX quote: tee_type=0x%08x", teeType)
	}

	var minSize int
	switch version {
	case 4:
		minSize = minQuoteSizeTD10
	case 5:
		minSize = minQuoteSizeTD15
	default:
		return nil, fmt.Errorf("tdx: unsupported quote version: %d", version)
	}
	if len(quote) < minSize {
		return nil, fmt.Errorf("tdx: quote too short for v%d body: %d < %d", version, len(quote), minSize)
	}

	// Bounds check above (len(quote) < minSize) guarantees every slice
	// expression below is within the buffer. gosec G602 has no
	// flow-sensitive analysis here and reports a false positive.
	body := quote[quoteHeaderSizeTDX:] //nolint:gosec // bounds checked
	out := &parsedTDXQuote{
		Version:    version,
		TeeType:    teeType,
		MRTD:       cloneSlice(body[bodyOffMRTD : bodyOffMRTD+sizeMeasurement]),               //nolint:gosec // bounds checked
		RTMR0:      cloneSlice(body[bodyOffRTMR0 : bodyOffRTMR0+sizeMeasurement]),             //nolint:gosec // bounds checked
		RTMR1:      cloneSlice(body[bodyOffRTMR1 : bodyOffRTMR1+sizeMeasurement]),             //nolint:gosec // bounds checked
		RTMR2:      cloneSlice(body[bodyOffRTMR2 : bodyOffRTMR2+sizeMeasurement]),             //nolint:gosec // bounds checked
		RTMR3:      cloneSlice(body[bodyOffRTMR3 : bodyOffRTMR3+sizeMeasurement]),             //nolint:gosec // bounds checked
		ReportData: cloneSlice(body[bodyOffReportData : bodyOffReportData+tdxReportDataSize]), //nolint:gosec // bounds checked
	}
	return out, nil
}

// cloneSlice returns a defensive copy so caller writes don't mutate the
// input. Returns a non-nil empty slice for an empty input so downstream
// length checks behave consistently.
func cloneSlice(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// isZero reports whether every byte in b is zero. Used by self-check to
// reject all-zero PCR/MRTD values that indicate the boot chain failed to
// extend the vTPM.
func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
