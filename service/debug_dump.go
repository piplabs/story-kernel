package service

// This file holds compact, allocation-light formatting helpers used purely for
// debug/forensic logging of DKG committee composition. They produce short,
// comparable fingerprints so the same committee logged from different code
// paths (chain-fetch vs store-rebuild) or different nodes/rounds can be diffed
// at a glance.
//
// Two committee sources diverge in resharing and are the focus of these dumps:
//   - chain-fetch path (GetAllParticipantDKGRegistrations): FILTERS OUT
//     INVALIDATED registrations, so a node invalidated this round disappears
//     (committee shrinks, e.g. 4 -> 3).
//   - store-rebuild path (rebuildResharing{Next,Prev}DKG): uses the PubKeys
//     persisted in DKGState, which were sealed while the node was still
//     VERIFIED and are NOT re-filtered, so the invalidated node REMAINS
//     (committee stays 4).
// When these two disagree, kyber derives a different sessionID and replayed
// deals fail Schnorr verification — hence dumping both with their source label.

import (
	"encoding/hex"
	"fmt"
	"strings"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
)

// fpLen is the number of leading bytes of a marshaled point used as its
// fingerprint in debug logs (8 hex chars is enough to disambiguate in practice
// while keeping log lines short).
const fpLen = 4

// fmtPubKeys renders a kyber.Point slice as "n=<count>[fp0,fp1,...]" where each
// fp is the hex of the point's leading bytes. Order is preserved so the same
// committee built two ways can be compared positionally.
func fmtPubKeys(pts []kyber.Point) string {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d[", len(pts))
	for i, p := range pts {
		if i > 0 {
			b.WriteByte(',')
		}
		if p == nil {
			b.WriteString("nil")
			continue
		}
		bz, err := p.MarshalBinary()
		if err != nil {
			b.WriteString("ERR")
			continue
		}
		if len(bz) > fpLen {
			bz = bz[:fpLen]
		}
		b.WriteString(hex.EncodeToString(bz))
	}
	b.WriteByte(']')

	return b.String()
}

// fmtPubKeyBytes is fmtPubKeys for already-marshaled points (e.g. stored
// PubKeys / PublicCoeffs as [][]byte).
func fmtPubKeyBytes(bzs [][]byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d[", len(bzs))
	for i, bz := range bzs {
		if i > 0 {
			b.WriteByte(',')
		}
		if len(bz) > fpLen {
			bz = bz[:fpLen]
		}
		b.WriteString(hex.EncodeToString(bz))
	}
	b.WriteByte(']')

	return b.String()
}

// fmtRegs renders a registration slice as "n=<count>[<addr10>#<index>:<status>,...]"
// so a chain-fetched committee (post-filter) can be compared against the
// active validator set to see exactly who was dropped (INVALIDATED) and who
// remained.
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
