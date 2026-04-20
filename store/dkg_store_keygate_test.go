package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/piplabs/story-kernel/config"
	"github.com/stretchr/testify/require"
)

// TestHasAnyDistKeyShareInDir_EmptyDir verifies that an empty directory returns false.
func TestHasAnyDistKeyShareInDir_EmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	has, err := HasAnyDistKeyShareInDir(dir)
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasAnyDistKeyShareInDir_NonExistentDir verifies that a non-existent directory returns false.
func TestHasAnyDistKeyShareInDir_NonExistentDir(t *testing.T) {
	t.Parallel()

	has, err := HasAnyDistKeyShareInDir("/nonexistent/path/that/does/not/exist")
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasAnyDistKeyShareInDir_WithDistKeyShare verifies that a directory containing
// a dist_key_share.sealed file in the expected nested structure returns true.
func TestHasAnyDistKeyShareInDir_WithDistKeyShare(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create the nested structure: {dir}/1/abcdef/dist_key_share.sealed
	shareDir := filepath.Join(dir, "1", "abcdef0123456789")
	require.NoError(t, os.MkdirAll(shareDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(shareDir, config.DistKeyShareFile), []byte("sealed-data"), 0o600))

	has, err := HasAnyDistKeyShareInDir(dir)
	require.NoError(t, err)
	require.True(t, has)
}

// TestHasAnyDistKeyShareInDir_MultipleRounds verifies detection across multiple round directories.
func TestHasAnyDistKeyShareInDir_MultipleRounds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Round 1 exists but has no dist_key_share.sealed
	round1Dir := filepath.Join(dir, "1", "commit_a")
	require.NoError(t, os.MkdirAll(round1Dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(round1Dir, DKGStateFile), []byte("{}"), 0o600))

	// Round 2 has a dist_key_share.sealed
	round2Dir := filepath.Join(dir, "2", "commit_b")
	require.NoError(t, os.MkdirAll(round2Dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(round2Dir, config.DistKeyShareFile), []byte("sealed-data"), 0o600))

	has, err := HasAnyDistKeyShareInDir(dir)
	require.NoError(t, err)
	require.True(t, has)
}

// TestHasAnyDistKeyShareInDir_OtherFilesOnly verifies that other sealed files
// (e.g., state.json, ed25519_priv.sealed) are not mistaken for dist_key_share.sealed.
func TestHasAnyDistKeyShareInDir_OtherFilesOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	roundDir := filepath.Join(dir, "1", "commit_a")
	require.NoError(t, os.MkdirAll(roundDir, 0o700))

	// Create other files that should NOT trigger the check
	require.NoError(t, os.WriteFile(filepath.Join(roundDir, DKGStateFile), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(roundDir, KeyEd25519File), []byte("key"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(roundDir, PrivateCoeffsFile), []byte("coeffs"), 0o600))

	has, err := HasAnyDistKeyShareInDir(dir)
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasAnyDistKeyShareInDir_FilesAtRoundLevel verifies that files directly
// under the state dir (not in the round/commit structure) are ignored.
func TestHasAnyDistKeyShareInDir_FilesAtRoundLevel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A file at the round level (not a directory) should be skipped
	require.NoError(t, os.WriteFile(filepath.Join(dir, "stray_file"), []byte("data"), 0o600))

	has, err := HasAnyDistKeyShareInDir(dir)
	require.NoError(t, err)
	require.False(t, has)
}

// TestHasAnyDistKeyShare_ViaMethod verifies the DKGStore method delegates correctly.
func TestHasAnyDistKeyShare_ViaMethod(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "dkg_state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))

	store := NewDKGStoreWithSealer(filepath.Join(dir, "keys"), stateDir, nil, nil)

	// Empty — no shares
	has, err := store.HasAnyDistKeyShare()
	require.NoError(t, err)
	require.False(t, has)

	// Create a dist_key_share.sealed
	shareDir := filepath.Join(stateDir, "5", "deadbeef")
	require.NoError(t, os.MkdirAll(shareDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(shareDir, config.DistKeyShareFile), []byte("sealed"), 0o600))

	has, err = store.HasAnyDistKeyShare()
	require.NoError(t, err)
	require.True(t, has)
}
