package server

import (
	"testing"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/piplabs/story-kernel/store"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// writeNewSessionNonce tests
// =============================================================================

// TestWriteNewSessionNonce generates a valid nonce and persists it.
func TestWriteNewSessionNonce(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	nonce, err := writeNewSessionNonce(db)
	require.NoError(t, err)
	require.Len(t, nonce, store.SessionNonceSize)

	// Verify it was persisted.
	stored, err := db.Get(sessionNonceKey)
	require.NoError(t, err)
	require.Equal(t, nonce, stored)
}

// TestWriteNewSessionNonce_OverwritesPrevious verifies that a second call
// replaces the nonce (not appends or fails).
func TestWriteNewSessionNonce_OverwritesPrevious(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	nonce1, err := writeNewSessionNonce(db)
	require.NoError(t, err)

	nonce2, err := writeNewSessionNonce(db)
	require.NoError(t, err)

	require.NotEqual(t, nonce1, nonce2, "each call must produce a fresh nonce")
}

// =============================================================================
// readSessionNonce tests
// =============================================================================

// TestReadSessionNonce_AfterWrite reads back a previously written nonce.
func TestReadSessionNonce_AfterWrite(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	written, err := writeNewSessionNonce(db)
	require.NoError(t, err)

	read, err := readSessionNonce(db)
	require.NoError(t, err)
	require.Equal(t, written, read)
}

// TestReadSessionNonce_EmptyDB returns error when no nonce exists.
func TestReadSessionNonce_EmptyDB(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	_, err := readSessionNonce(db)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestReadSessionNonce_CorruptedLength returns error when nonce has wrong length.
func TestReadSessionNonce_CorruptedLength(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()
	require.NoError(t, db.Set(sessionNonceKey, []byte("too-short")))

	_, err := readSessionNonce(db)
	require.Error(t, err)
	require.Contains(t, err.Error(), "corrupted")
}
