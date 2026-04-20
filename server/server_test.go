package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/piplabs/story-kernel/config"
	"github.com/stretchr/testify/require"
)

// TestRejectConfigFallbackIfDKGKeysExist_NoKeys verifies that first-boot
// (no dist_key_share.sealed anywhere) is allowed through.
func TestRejectConfigFallbackIfDKGKeysExist_NoKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.SetHomeDir(dir)

	// Ensure the DKG state directory exists but is empty.
	require.NoError(t, os.MkdirAll(cfg.GetDKGStateDir(), 0o700))

	err := rejectConfigFallbackIfDKGKeysExist(cfg)
	require.NoError(t, err, "first boot with no DKG keys should be allowed")
}

// TestRejectConfigFallbackIfDKGKeysExist_WithKeys verifies that the fallback
// is rejected when sealed DKG key shares exist.
func TestRejectConfigFallbackIfDKGKeysExist_WithKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.SetHomeDir(dir)

	// Create a dist_key_share.sealed in the expected structure.
	shareDir := filepath.Join(cfg.GetDKGStateDir(), "1", "abcdef0123456789")
	require.NoError(t, os.MkdirAll(shareDir, 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(shareDir, config.DistKeyShareFile),
		[]byte("sealed-data"), 0o600,
	))

	err := rejectConfigFallbackIfDKGKeysExist(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sealed DKG key shares exist")
	require.Contains(t, err.Error(), "re-register")
}

// TestRejectConfigFallbackIfDKGKeysExist_NoDKGStateDir verifies that a missing
// DKG state directory (completely fresh install) is allowed.
func TestRejectConfigFallbackIfDKGKeysExist_NoDKGStateDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.SetHomeDir(dir)

	// Do NOT create the DKG state directory — simulate fresh install.
	err := rejectConfigFallbackIfDKGKeysExist(cfg)
	require.NoError(t, err, "fresh install with no DKG state dir should be allowed")
}
