package store

import (
	"fmt"
	"strconv"
	"sync"

	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

type RoundContext struct {
	Round uint32

	Network       *pb.DKGNetwork
	Registrations []*pb.DKGRegistration
	SortedPubKeys []kyber.Point
}

type RoundContextCache struct {
	mu    sync.RWMutex
	items map[uint32]*RoundContext
}

func NewRoundContextCache() *RoundContextCache {
	return &RoundContextCache{
		items: make(map[uint32]*RoundContext),
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

	c.items[round] = rc
}

type DKGCache struct {
	mu    sync.RWMutex
	cache map[string]*dkg.DistKeyGenerator
}

func NewDKGCache() *DKGCache {
	return &DKGCache{
		cache: make(map[string]*dkg.DistKeyGenerator),
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

	c.cache[strconv.FormatUint(uint64(round), 10)] = distKeyGen
}

type ResharingCache DKGCache

func NewResharingDKGCache() *ResharingCache {
	return &ResharingCache{
		cache: make(map[string]*dkg.DistKeyGenerator),
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

	c.cache[fmt.Sprintf("%d_%d", fromRound, toRound)] = distKeyGen
}

type DistKeyShareCache struct {
	mu    sync.RWMutex
	cache map[uint32]*dkg.DistKeyShare
}

func NewDistKeyShareCache() *DistKeyShareCache {
	return &DistKeyShareCache{
		cache: make(map[uint32]*dkg.DistKeyShare),
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
	c.cache[round] = distKeyShare
}

// PIDCache stores the 1-based PID for each round, derived during SetupDKGNetwork.
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
