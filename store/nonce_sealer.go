package store

import (
	"bytes"
	"fmt"
)

const (
	// SessionNonceSize is the byte length of the session nonce used to bind
	// sealed files to a specific light client DB instance.
	SessionNonceSize = 32
)

// NonceBindingSealer wraps a Sealer to prepend a session nonce to all sealed data.
// On seal, the nonce is prepended before the payload.
// On unseal, the nonce prefix is verified against the expected nonce.
//
// This ensures that sealed files created under one light client DB session
// cannot be used with a different DB instance. The in-memory cache
// (DistKeyShareCache) is safe because it is cleared on restart, and a restart
// is required to change the DB session nonce.
type NonceBindingSealer struct {
	inner Sealer
	nonce []byte // SessionNonceSize bytes
}

// NewNonceBindingSealer creates a NonceBindingSealer that wraps inner with the
// given session nonce. The nonce must be exactly SessionNonceSize bytes.
func NewNonceBindingSealer(inner Sealer, nonce []byte) (*NonceBindingSealer, error) {
	if len(nonce) != SessionNonceSize {
		return nil, fmt.Errorf("session nonce must be %d bytes, got %d", SessionNonceSize, len(nonce))
	}

	cp := make([]byte, SessionNonceSize)
	copy(cp, nonce)

	return &NonceBindingSealer{inner: inner, nonce: cp}, nil
}

// SealToFile prepends the session nonce to data and delegates to the inner Sealer.
func (s *NonceBindingSealer) SealToFile(data []byte, path string) error {
	bound := make([]byte, len(s.nonce)+len(data))
	copy(bound, s.nonce)
	copy(bound[len(s.nonce):], data)

	return s.inner.SealToFile(bound, path)
}

// UnsealFromFile delegates to the inner Sealer and verifies the session nonce prefix.
// Returns an error if the unsealed data is too short or the nonce does not match.
func (s *NonceBindingSealer) UnsealFromFile(path string) ([]byte, error) {
	raw, err := s.inner.UnsealFromFile(path)
	if err != nil {
		return nil, err
	}

	if len(raw) < len(s.nonce) {
		return nil, fmt.Errorf("session nonce mismatch: sealed data too short (expected at least %d bytes, got %d)", len(s.nonce), len(raw))
	}

	if !bytes.Equal(raw[:len(s.nonce)], s.nonce) {
		return nil, fmt.Errorf("session nonce mismatch: sealed data was created in a different DB session")
	}

	return raw[len(s.nonce):], nil
}
