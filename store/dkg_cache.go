package store

import (
	"fmt"
	"strconv"
	"sync"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// maxCacheSize is the maximum number of entries per DKG cache.
// In practice at most 2 rounds are active concurrently; this limit
// is a safety net against unbounded memory growth.
const maxCacheSize = 10

type RoundContext struct {
	Round uint32

	Network       *pb.DKGNetwork
	Registrations []*pb.DKGRegistration
	SortedPubKeys []kyber.Point
}

type RoundContextCache struct {
	mu      sync.RWMutex
	items   map[uint32]*RoundContext
	order   []uint32
	maxSize int
}

func NewRoundContextCache() *RoundContextCache {
	return &RoundContextCache{
		items:   make(map[uint32]*RoundContext),
		maxSize: maxCacheSize,
	}
}

func (c *RoundContextCache) Get(round uint32) (*RoundContext, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rc, ok := c.items[round]

	return rc, ok
}

func (c *RoundContextCache) Set(round uint32, rc *RoundContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[round]; !exists {
		c.evictIfFull()
		c.order = append(c.order, round)
	}
	c.items[round] = rc
}

// evictIfFull removes the oldest entry when the cache is at capacity.
// Must be called while holding c.mu write lock.
func (c *RoundContextCache) evictIfFull() {
	if len(c.items) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}

type DKGCache struct {
	mu      sync.RWMutex
	cache   map[string]*dkg.DistKeyGenerator
	order   []string // insertion order for eviction
	maxSize int
}

func NewDKGCache() *DKGCache {
	return &DKGCache{
		cache:   make(map[string]*dkg.DistKeyGenerator),
		maxSize: maxCacheSize,
	}
}

func (c *DKGCache) Get(round uint32) (*dkg.DistKeyGenerator, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	distKeyGen, ok := c.cache[strconv.FormatUint(uint64(round), 10)]

	return distKeyGen, ok
}

func (c *DKGCache) Set(round uint32, distKeyGen *dkg.DistKeyGenerator) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := strconv.FormatUint(uint64(round), 10)
	if _, exists := c.cache[key]; !exists {
		c.evictIfFull()
		c.order = append(c.order, key)
	}
	c.cache[key] = distKeyGen
}

// evictIfFull removes the oldest entry when the cache is at capacity.
// Must be called while holding c.mu write lock.
func (c *DKGCache) evictIfFull() {
	if len(c.cache) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}
}

type ResharingCache struct {
	mu      sync.RWMutex
	cache   map[string]*dkg.DistKeyGenerator
	order   []string // insertion order for eviction
	maxSize int
}

func NewResharingDKGCache() *ResharingCache {
	return &ResharingCache{
		cache:   make(map[string]*dkg.DistKeyGenerator),
		maxSize: maxCacheSize,
	}
}

func (c *ResharingCache) Get(fromRound, toRound uint32) (*dkg.DistKeyGenerator, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	distKeyGen, ok := c.cache[fmt.Sprintf("%d_%d", fromRound, toRound)]

	return distKeyGen, ok
}

func (c *ResharingCache) Set(fromRound, toRound uint32, distKeyGen *dkg.DistKeyGenerator) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%d_%d", fromRound, toRound)
	if _, exists := c.cache[key]; !exists {
		c.evictIfFull()
		c.order = append(c.order, key)
	}
	c.cache[key] = distKeyGen
}

// evictIfFull removes the oldest entry when the cache is at capacity.
// Must be called while holding c.mu write lock.
func (c *ResharingCache) evictIfFull() {
	if len(c.cache) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}
}

type DistKeyShareCache struct {
	mu      sync.RWMutex
	cache   map[uint32]*dkg.DistKeyShare
	order   []uint32 // insertion order for eviction
	maxSize int
}

func NewDistKeyShareCache() *DistKeyShareCache {
	return &DistKeyShareCache{
		cache:   make(map[uint32]*dkg.DistKeyShare),
		maxSize: maxCacheSize,
	}
}

func (c *DistKeyShareCache) Get(round uint32) (*dkg.DistKeyShare, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	distKeyShare, ok := c.cache[round]

	return distKeyShare, ok
}

func (c *DistKeyShareCache) Set(round uint32, distKeyShare *dkg.DistKeyShare) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.cache[round]; !exists {
		c.evictIfFull()
		c.order = append(c.order, round)
	}
	c.cache[round] = distKeyShare
}

// evictIfFull removes the oldest entry when the cache is at capacity.
// Must be called while holding c.mu write lock.
func (c *DistKeyShareCache) evictIfFull() {
	if len(c.cache) >= c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}
}

// PIDCache stores the 1-based PID for each round, derived during SetupDKGNetwork.
// No eviction — entries are uint32 pairs (~8 bytes each) and accumulate slowly.
type PIDCache struct {
	mu    sync.RWMutex
	cache map[uint32]uint32 // round -> 1-based PID
}

func NewPIDCache() *PIDCache {
	return &PIDCache{
		cache: make(map[uint32]uint32),
	}
}

func (c *PIDCache) Get(round uint32) (uint32, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pid, ok := c.cache[round]

	return pid, ok
}

func (c *PIDCache) Set(round uint32, pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[round] = pid
}
