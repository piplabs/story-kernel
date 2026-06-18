package story

// Compact formatting helpers for debug/forensic logging in the verified-query
// client. Kept in the `story` package (separate from service.debug_dump.go,
// which serves the service package) so committee composition fetched from the
// chain can be logged in the same comparable shape as the committee rebuilt
// from sealed state.

import (
	"encoding/hex"
	"fmt"
	"strings"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// fmtRegs renders a registration slice as "n=<count>[<addr10>#<index>:<status>,...]".
func fmtRegs(regs []*pb.DKGRegistration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d[", len(regs))
	for i, r := range regs {
		if i > 0 {
			b.WriteByte(',')
		}
		if r == nil {
			b.WriteString("nil")
			continue
		}
		addr := r.GetValidatorAddr()
		if len(addr) > 10 {
			addr = addr[:10]
		}
		fmt.Fprintf(&b, "%s#%d:%s", addr, r.GetIndex(), shortStatus(r.GetStatus()))
	}
	b.WriteByte(']')

	return b.String()
}

// shortStatus maps a DKG registration status to a short readable label.
func shortStatus(st pb.DKGRegStatus) string {
	switch st {
	case pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED:
		return "VER"
	case pb.DKGRegStatus_DKG_REG_STATUS_FINALIZED:
		return "FIN"
	case pb.DKGRegStatus_DKG_REG_STATUS_INVALIDATED:
		return "INV"
	default:
		return st.String()
	}
}

// fmtAddrs renders a plain validator-address slice (e.g. ActiveValSet) as
// "n=<count>[<addr10>,...]".
func fmtAddrs(addrs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d[", len(addrs))
	for i, a := range addrs {
		if i > 0 {
			b.WriteByte(',')
		}
		if len(a) > 10 {
			a = a[:10]
		}
		b.WriteString(a)
	}
	b.WriteByte(']')

	return b.String()
}

// hexHead returns a short hex prefix of a byte slice for debug logging, with
// the total length appended so a truncated fingerprint is never mistaken for
// the full value. Example: "a1b2c3d4..(len=33)".
func hexHead(bz []byte) string {
	const head = 8
	if len(bz) <= head {
		return hex.EncodeToString(bz)
	}

	return fmt.Sprintf("%s..(len=%d)", hex.EncodeToString(bz[:head]), len(bz))
}
