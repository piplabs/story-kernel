package store

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// =============================================================================
// RoundContextCache tests
// =============================================================================

// TestRoundContextCache_SetGet verifies basic Set/Get operations.
func TestRoundContextCache_SetGet(t *testing.T) {
	t.Parallel()

	cache := NewRoundContextCache()

	// Miss before any entry is set
	_, ok := cache.Get(1)
	require.False(t, ok, "expected cache miss for round 1")

	rc := &RoundContext{
		Round:   1,
		Network: &pb.DKGNetwork{Round: 1},
	}
	cache.Set(1, rc)

	got, ok := cache.Get(1)
	require.True(t, ok, "expected cache hit after Set")
	require.Equal(t, uint32(1), got.Round)
}

// TestRoundContextCache_MultipleRounds verifies that multiple rounds are stored independently.
func TestRoundContextCache_MultipleRounds(t *testing.T) {
	t.Parallel()

	cache := NewRoundContextCache()

	for i := uint32(1); i <= 5; i++ {
		cache.Set(i, &RoundContext{Round: i})
	}

	for i := uint32(1); i <= 5; i++ {
		got, ok := cache.Get(i)
		require.True(t, ok)
		require.Equal(t, i, got.Round)
	}

	// Round 6 was never set
	_, ok := cache.Get(6)
	require.False(t, ok)
}

// TestRoundContextCache_Overwrite verifies that Set overwrites an existing entry.
func TestRoundContextCache_Overwrite(t *testing.T) {
	t.Parallel()

	cache := NewRoundContextCache()
	cache.Set(1, &RoundContext{Round: 1})
	cache.Set(1, &RoundContext{Round: 99})

	got, ok := cache.Get(1)
	require.True(t, ok)
	require.Equal(t, uint32(99), got.Round)
}

// TestRoundContextCache_Concurrent exercises concurrent access under the race detector.
func TestRoundContextCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := NewRoundContextCache()
	var wg sync.WaitGroup

	for i := uint32(0); i < 50; i++ {
		wg.Add(2)
		round := i
		go func() {
			defer wg.Done()
			cache.Set(round, &RoundContext{Round: round})
		}()
		go func() {
			defer wg.Done()
			cache.Get(round)
		}()
	}
	wg.Wait()
}

// =============================================================================
// DKGCache tests
// =============================================================================

// TestDKGCache_SetGet verifies basic Set/Get operations.
func TestDKGCache_SetGet(t *testing.T) {
	t.Parallel()

	cache := NewDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Miss before any entry is set
	_, ok := cache.Get(1)
	require.False(t, ok)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	cache.Set(1, dkgGen)

	got, ok := cache.Get(1)
	require.True(t, ok)
	require.NotNil(t, got)
}

// TestDKGCache_MissOnDifferentRound verifies that different rounds are not confused.
func TestDKGCache_MissOnDifferentRound(t *testing.T) {
	t.Parallel()

	cache := NewDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	cache.Set(1, dkgGen)

	_, ok := cache.Get(2)
	require.False(t, ok, "round 2 should not be in cache")
}

// TestDKGCache_Concurrent exercises concurrent access.
func TestDKGCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := NewDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := uint32(0); i < 20; i++ {
		wg.Add(2)
		round := i
		go func() {
			defer wg.Done()
			cache.Set(round, dkgGen)
		}()
		go func() {
			defer wg.Done()
			cache.Get(round)
		}()
	}
	wg.Wait()
}

// =============================================================================
// ResharingCache tests
// =============================================================================

// TestResharingCache_SetGet verifies basic Set/Get operations with two round keys.
func TestResharingCache_SetGet(t *testing.T) {
	t.Parallel()

	cache := NewResharingDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Miss before any entry is set
	_, ok := cache.Get(1, 2)
	require.False(t, ok)

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	cache.Set(1, 2, dkgGen)

	got, ok := cache.Get(1, 2)
	require.True(t, ok)
	require.NotNil(t, got)
}

// TestResharingCache_DifferentPairsDoNotCollide verifies key uniqueness.
func TestResharingCache_DifferentPairsDoNotCollide(t *testing.T) {
	t.Parallel()

	cache := NewResharingDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	cache.Set(1, 2, dkgGen)

	// (2, 1) and (1, 3) should both miss
	_, ok := cache.Get(2, 1)
	require.False(t, ok, "(2,1) should not be in cache when only (1,2) was set")

	_, ok = cache.Get(1, 3)
	require.False(t, ok, "(1,3) should not be in cache when only (1,2) was set")
}

// TestResharingCache_Concurrent exercises concurrent access.
func TestResharingCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := NewResharingDKGCache()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := uint32(0); i < 20; i++ {
		wg.Add(2)
		from, to := i, i+1
		go func() {
			defer wg.Done()
			cache.Set(from, to, dkgGen)
		}()
		go func() {
			defer wg.Done()
			cache.Get(from, to)
		}()
	}
	wg.Wait()
}

// =============================================================================
// DistKeyShareCache tests
// =============================================================================

// TestDistKeyShareCache_SetGet verifies basic Set/Get operations.
func TestDistKeyShareCache_SetGet(t *testing.T) {
	t.Parallel()

	cache := NewDistKeyShareCache()

	// Miss before any entry is set
	_, ok := cache.Get(1)
	require.False(t, ok)

	dks := &dkg.DistKeyShare{}
	cache.Set(1, dks)

	got, ok := cache.Get(1)
	require.True(t, ok)
	require.NotNil(t, got)
}

// TestDistKeyShareCache_Concurrent exercises concurrent access.
func TestDistKeyShareCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := NewDistKeyShareCache()
	dks := &dkg.DistKeyShare{}

	var wg sync.WaitGroup
	for i := uint32(0); i < 20; i++ {
		wg.Add(2)
		round := i
		go func() {
			defer wg.Done()
			cache.Set(round, dks)
		}()
		go func() {
			defer wg.Done()
			cache.Get(round)
		}()
	}
	wg.Wait()
}

// =============================================================================
// PIDCache tests
// =============================================================================

// TestPIDCache_SetGet verifies basic Set/Get operations.
func TestPIDCache_SetGet(t *testing.T) {
	t.Parallel()

	cache := NewPIDCache()

	// Miss before any entry is set
	_, ok := cache.Get(1)
	require.False(t, ok)

	cache.Set(1, 42)

	pid, ok := cache.Get(1)
	require.True(t, ok)
	require.Equal(t, uint32(42), pid)
}

// TestPIDCache_Overwrite verifies that Set overwrites an existing entry.
func TestPIDCache_Overwrite(t *testing.T) {
	t.Parallel()

	cache := NewPIDCache()
	cache.Set(1, 10)
	cache.Set(1, 20)

	pid, ok := cache.Get(1)
	require.True(t, ok)
	require.Equal(t, uint32(20), pid)
}

// TestPIDCache_Concurrent exercises concurrent access under the race detector.
func TestPIDCache_Concurrent(t *testing.T) {
	t.Parallel()

	cache := NewPIDCache()

	var wg sync.WaitGroup
	for i := uint32(0); i < 50; i++ {
		wg.Add(2)
		round := i
		go func() {
			defer wg.Done()
			cache.Set(round, round+1)
		}()
		go func() {
			defer wg.Done()
			cache.Get(round)
		}()
	}
	wg.Wait()
}

func TestDKGCache_MaxSize(t *testing.T) {
	t.Parallel()
	c := NewDKGCache()
	// Override maxSize for testing
	c.maxSize = 3

	// Fill cache to capacity
	c.Set(1, nil)
	c.Set(2, nil)
	c.Set(3, nil)

	_, ok := c.Get(1)
	require.True(t, ok, "round 1 should still be present")

	// Adding a 4th entry should evict the oldest (round 1)
	c.Set(4, nil)

	_, ok = c.Get(1)
	assert.False(t, ok, "round 1 should have been evicted")

	_, ok = c.Get(2)
	assert.True(t, ok, "round 2 should still be present")

	_, ok = c.Get(4)
	assert.True(t, ok, "round 4 should be present")
}

func TestDKGCache_UpdateExistingDoesNotEvict(t *testing.T) {
	t.Parallel()
	c := NewDKGCache()
	c.maxSize = 2

	c.Set(1, nil)
	c.Set(2, nil)

	// Updating an existing key should not trigger eviction
	c.Set(1, nil)

	_, ok := c.Get(1)
	assert.True(t, ok)
	_, ok = c.Get(2)
	assert.True(t, ok)
}

func TestResharingCache_MaxSize(t *testing.T) {
	t.Parallel()
	c := NewResharingDKGCache()
	c.maxSize = 2

	c.Set(1, 2, nil)
	c.Set(2, 3, nil)

	_, ok := c.Get(1, 2)
	require.True(t, ok)

	// Evicts (1,2)
	c.Set(3, 4, nil)

	_, ok = c.Get(1, 2)
	assert.False(t, ok, "oldest entry should have been evicted")

	_, ok = c.Get(3, 4)
	assert.True(t, ok)
}

func TestDistKeyShareCache_MaxSize(t *testing.T) {
	t.Parallel()
	c := NewDistKeyShareCache()
	c.maxSize = 2

	c.Set(10, nil)
	c.Set(20, nil)

	_, ok := c.Get(10)
	require.True(t, ok)

	// Evicts round 10
	c.Set(30, nil)

	_, ok = c.Get(10)
	assert.False(t, ok, "oldest entry should have been evicted")

	_, ok = c.Get(20)
	assert.True(t, ok)

	_, ok = c.Get(30)
	assert.True(t, ok)
}

func TestDistKeyShareCache_UpdateExistingDoesNotEvict(t *testing.T) {
	t.Parallel()
	c := NewDistKeyShareCache()
	c.maxSize = 2

	c.Set(1, nil)
	c.Set(2, nil)

	// Updating existing key should not trigger eviction
	c.Set(2, nil)

	_, ok := c.Get(1)
	assert.True(t, ok)
	_, ok = c.Get(2)
	assert.True(t, ok)
}

func TestMaxCacheSize_Constant(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 10, maxCacheSize)
}
