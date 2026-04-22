package store

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNonceBindingSealer_RoundTrip verifies that data sealed with the correct
// nonce can be unsealed successfully.
func TestNonceBindingSealer_RoundTrip(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.sealed")
	payload := []byte("hello world")

	require.NoError(t, sealer.SealToFile(payload, path))

	got, err := sealer.UnsealFromFile(path)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// TestNonceBindingSealer_WrongNonce verifies that data sealed with one nonce
// cannot be unsealed with a different nonce.
func TestNonceBindingSealer_WrongNonce(t *testing.T) {
	t.Parallel()

	nonce1 := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce1)
	require.NoError(t, err)

	nonce2 := make([]byte, SessionNonceSize)
	_, err = rand.Read(nonce2)
	require.NoError(t, err)

	sealer1, err := NewNonceBindingSealer(plaintextSealer{}, nonce1)
	require.NoError(t, err)
	sealer2, err := NewNonceBindingSealer(plaintextSealer{}, nonce2)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "test.sealed")
	payload := []byte("secret data")

	require.NoError(t, sealer1.SealToFile(payload, path))

	_, err = sealer2.UnsealFromFile(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "session nonce mismatch")
}

// TestNonceBindingSealer_DataTooShort verifies that data shorter than the nonce
// length returns an error.
func TestNonceBindingSealer_DataTooShort(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "short.sealed")

	// Write raw data shorter than nonce length (bypass NonceBindingSealer)
	require.NoError(t, os.WriteFile(path, []byte("short"), 0o600))

	_, err = sealer.UnsealFromFile(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

// TestNonceBindingSealer_EmptyPayload verifies that sealing and unsealing an
// empty payload works correctly (nonce-only file).
func TestNonceBindingSealer_EmptyPayload(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.sealed")

	require.NoError(t, sealer.SealToFile([]byte{}, path))

	got, err := sealer.UnsealFromFile(path)
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestNonceBindingSealer_PrependsAndStripsNonce verifies the raw file content
// has the nonce prepended, and unsealing strips it correctly.
func TestNonceBindingSealer_PrependsAndStripsNonce(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "check.sealed")
	payload := []byte("payload-data")

	require.NoError(t, sealer.SealToFile(payload, path))

	// Read raw file to verify nonce is prepended (plaintextSealer writes raw)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, raw, SessionNonceSize+len(payload))
	require.Equal(t, nonce, raw[:SessionNonceSize])
	require.Equal(t, payload, raw[SessionNonceSize:])
}

// TestNonceBindingSealer_InnerUnsealError verifies that errors from the inner
// sealer are propagated.
func TestNonceBindingSealer_InnerUnsealError(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	_, err = sealer.UnsealFromFile("/nonexistent/path/file.sealed")
	require.Error(t, err)
}

// TestNewNonceBindingSealer_InvalidNonceLength verifies that nonces with wrong
// length are rejected.
func TestNewNonceBindingSealer_InvalidNonceLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		nonce []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewNonceBindingSealer(plaintextSealer{}, tt.nonce)
			require.Error(t, err)
			require.Contains(t, err.Error(), "session nonce must be")
		})
	}
}

// TestNonceBindingSealer_ImplementsSealer verifies that NonceBindingSealer
// satisfies the Sealer interface at compile time.
func TestNonceBindingSealer_ImplementsSealer(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, SessionNonceSize)
	sealer, err := NewNonceBindingSealer(plaintextSealer{}, nonce)
	require.NoError(t, err)

	var _ Sealer = sealer
}
