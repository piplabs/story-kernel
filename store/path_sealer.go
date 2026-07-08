package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
)

// pathBindingIDComponents is the number of trailing path components that
// identify a sealed slot: {round}/{codeCommitment}/{filename}. Binding these
// into the authenticated payload makes a sealed blob recoverable only at the
// exact slot it was sealed for.
const pathBindingIDComponents = 3

// pathBindingHeaderLen is the fixed-size length prefix (uint16) that precedes
// the bound slot identity in the framed payload.
const pathBindingHeaderLen = 2

// PathBindingSealer wraps a Sealer and binds each sealed file to its logical
// slot identity (the trailing path components), authenticated by the
// underlying seal. A host with write access to the (writable) DKG data
// partition can copy one sealed blob over another slot (relocation) or restore
// an old round's blob into the current slot (stale-share replay); the
// underlying GCM/enclave seal accepts either because the sealing key and PCR
// policy are storage-context-free. Framing the slot identity into the
// authenticated payload makes both fail on unseal: the identity read back must
// equal the identity derived from the path being read.
//
// The round number is part of the identity, so restoring round N-1's blob into
// round N's slot is caught as a mismatch — the stale-share defense the DKG data
// partition needs on top of the session-nonce binding.
type PathBindingSealer struct {
	inner Sealer
}

// NewPathBindingSealer wraps inner with per-file slot-identity binding.
func NewPathBindingSealer(inner Sealer) *PathBindingSealer {
	return &PathBindingSealer{inner: inner}
}

// pathBindingID returns the stable slot identity for path: the trailing
// pathBindingIDComponents path components joined with "/". It is independent of
// the store root (keyDir/stateDir), so relocating the whole home directory does
// not invalidate blobs, but moving a blob between round/commitment slots does.
func pathBindingID(path string) []byte {
	parts := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	if len(parts) > pathBindingIDComponents {
		parts = parts[len(parts)-pathBindingIDComponents:]
	}
	return []byte(strings.Join(parts, "/"))
}

// SealToFile frames the slot identity into the payload, then delegates to the
// inner Sealer (which handles session-nonce binding and the TEE seal).
func (s *PathBindingSealer) SealToFile(data []byte, path string) error {
	id := pathBindingID(path)
	if len(id) > 0xFFFF {
		return fmt.Errorf("path binding: slot identity too long (%d bytes)", len(id))
	}

	bound := make([]byte, pathBindingHeaderLen+len(id)+len(data))
	binary.BigEndian.PutUint16(bound[:pathBindingHeaderLen], uint16(len(id)))
	copy(bound[pathBindingHeaderLen:], id)
	copy(bound[pathBindingHeaderLen+len(id):], data)

	return s.inner.SealToFile(bound, path)
}

// UnsealFromFile delegates to the inner Sealer, then verifies the bound slot
// identity against the path being read. A mismatch means the blob was relocated
// or replayed from another slot.
func (s *PathBindingSealer) UnsealFromFile(path string) ([]byte, error) {
	raw, err := s.inner.UnsealFromFile(path)
	if err != nil {
		return nil, err
	}

	if len(raw) < pathBindingHeaderLen {
		return nil, fmt.Errorf("path binding: sealed data too short (%d bytes)", len(raw))
	}
	idLen := int(binary.BigEndian.Uint16(raw[:pathBindingHeaderLen]))
	if len(raw) < pathBindingHeaderLen+idLen {
		return nil, fmt.Errorf("path binding: sealed data truncated (need %d bytes, got %d)", pathBindingHeaderLen+idLen, len(raw))
	}

	gotID := raw[pathBindingHeaderLen : pathBindingHeaderLen+idLen]
	wantID := pathBindingID(path)
	if !bytes.Equal(gotID, wantID) {
		return nil, fmt.Errorf("path binding mismatch: sealed for %q but read at %q", gotID, wantID)
	}

	return raw[pathBindingHeaderLen+idLen:], nil
}
