package story

import (
	"context"
	"sync"
	"testing"
	"time"

	cmtdb "github.com/cometbft/cometbft-db"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// HasTrustedState tests
// =============================================================================

// TestHasTrustedState_EmptyDB verifies that an empty in-memory DB returns false.
func TestHasTrustedState_EmptyDB(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()
	has, err := HasTrustedState(db, "test-chain")
	require.NoError(t, err)
	require.False(t, has, "empty DB should have no trusted state")
}

// TestHasTrustedState_DifferentChainIDs verifies that different chain IDs
// produce independent results (no cross-contamination in the key space).
func TestHasTrustedState_DifferentChainIDs(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	// Both chains should have no state on the same empty DB.
	hasA, err := HasTrustedState(db, "chain-a")
	require.NoError(t, err)
	require.False(t, hasA)

	hasB, err := HasTrustedState(db, "chain-b")
	require.NoError(t, err)
	require.False(t, hasB)
}

// TestHasTrustedState_EmptyChainID verifies that an empty chain ID is handled
// without panic or unexpected error.
func TestHasTrustedState_EmptyChainID(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()
	has, err := HasTrustedState(db, "")
	require.NoError(t, err)
	require.False(t, has)
}

// =============================================================================
// ClearTrustedState tests
// =============================================================================

// TestClearTrustedState_EmptyDB verifies that clearing an empty DB is a no-op.
func TestClearTrustedState_EmptyDB(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()
	err := ClearTrustedState(db, "test-chain")
	require.NoError(t, err)

	// DB should still be empty after clearing.
	has, err := HasTrustedState(db, "test-chain")
	require.NoError(t, err)
	require.False(t, has)
}

// TestClearTrustedState_DifferentChainIDs verifies clearing one chain ID
// does not affect another chain ID's key space.
func TestClearTrustedState_DifferentChainIDs(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()

	// Clear chain-a — should not cause errors.
	err := ClearTrustedState(db, "chain-a")
	require.NoError(t, err)

	// chain-b should also be unaffected.
	has, err := HasTrustedState(db, "chain-b")
	require.NoError(t, err)
	require.False(t, has)
}

// TestClearTrustedState_EmptyChainID verifies that an empty chain ID does not panic.
func TestClearTrustedState_EmptyChainID(t *testing.T) {
	t.Parallel()

	db := cmtdb.NewMemDB()
	err := ClearTrustedState(db, "")
	require.NoError(t, err)
}

// =============================================================================
// VerifyStartBlock input validation tests
// =============================================================================

// TestVerifyStartBlock_InvalidHeight verifies that a non-positive height is rejected
// before any light client call is made.
func TestVerifyStartBlock_InvalidHeight(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{
		mutex: &sync.Mutex{},
		// lightClient is intentionally nil; validation should short-circuit before use.
	}

	tests := []struct {
		name   string
		height int64
	}{
		{"zero height", 0},
		{"negative height", -1},
		{"min int64", -9223372036854775808},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := q.VerifyStartBlock(context.Background(), tc.height, []byte("hash"))
			require.ErrorContains(t, err, "invalid start block height")
		})
	}
}

// TestVerifyStartBlock_EmptyHash verifies that an empty block hash is rejected
// before any light client call is made.
func TestVerifyStartBlock_EmptyHash(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{
		mutex: &sync.Mutex{},
		// lightClient is intentionally nil; validation should short-circuit before use.
	}

	err := q.VerifyStartBlock(context.Background(), 1, []byte{})
	require.ErrorContains(t, err, "start block hash is empty")
}

// TestVerifyStartBlock_NilHash verifies that a nil block hash is rejected.
func TestVerifyStartBlock_NilHash(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{
		mutex: &sync.Mutex{},
	}

	err := q.VerifyStartBlock(context.Background(), 1, nil)
	require.ErrorContains(t, err, "start block hash is empty")
}

// =============================================================================
// getQueryBlockHeight tests
// =============================================================================

// TestGetQueryBlockHeight_ZeroCache verifies that zero cached height is clamped to 1.
func TestGetQueryBlockHeight_ZeroCache(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{cachedLastBlockHeight: 0}
	require.Equal(t, int64(1), q.getQueryBlockHeight())
}

// TestGetQueryBlockHeight_NegativeCache verifies that negative cached height is clamped to 1.
func TestGetQueryBlockHeight_NegativeCache(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{cachedLastBlockHeight: -5}
	require.Equal(t, int64(1), q.getQueryBlockHeight())
}

// TestGetQueryBlockHeight_PositiveCache verifies that a positive cached height is returned as-is.
func TestGetQueryBlockHeight_PositiveCache(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{cachedLastBlockHeight: 42}
	require.Equal(t, int64(42), q.getQueryBlockHeight())
}

// =============================================================================
// startSchedulingLastBlockCaching context cancellation test
// =============================================================================

// TestStartSchedulingLastBlockCaching_CancelStop verifies that the goroutine
// exits promptly when its context is cancelled.
func TestStartSchedulingLastBlockCaching_CancelStop(t *testing.T) {
	t.Parallel()

	q := &VerifiedQueryClient{
		cachedLastBlockHeight: 1,
		// rpcClient is nil; the goroutine only exits on ctx.Done() in this test
		// because the ticker fires much less frequently than the cancel below.
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		// startSchedulingLastBlockCaching is an infinite loop; it must return
		// after ctx is cancelled.
		q.startSchedulingLastBlockCaching(ctx)
		close(done)
	}()

	// Cancel immediately — the goroutine should exit.
	cancel()

	select {
	case <-done:
		// goroutine exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("startSchedulingLastBlockCaching did not exit after context cancellation")
	}
}
