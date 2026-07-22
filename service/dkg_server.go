package service

import (
	"sync"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

type DKGServer struct {
	pb.UnsafeKernelServiceServer

	Cfg                *config.Config
	QueryClient        story.QueryClient
	Suite              *edwards25519.SuiteEd25519
	RoundCtxCache      *store.RoundContextCache
	InitDKGCache       *store.DKGCache
	ResharingPrevCache *store.ResharingCache
	ResharingNextCache *store.DKGCache
	DistKeyShareCache  *store.DistKeyShareCache
	DKGStore           *store.DKGStore
	PIDCache           *store.PIDCache

	// Per-round mutexes prevent concurrent RPCs from both observing a cache
	// miss and racing to build+save the same DKG state.
	initDKGMu     sync.Map // map[uint32]*sync.Mutex
	resharePrevMu sync.Map // map[uint64]*sync.Mutex  (fromRound<<32 | toRound)
	reshareNextMu sync.Map // map[uint32]*sync.Mutex

	// dkgMutationMu serializes the DKG-mutating RPCs (ProcessDeals,
	// ProcessResponses, ProcessJustification, GenerateDeals, FinalizeDKG) for a
	// round. The cached
	// DistKeyGenerator is unsynchronized; a client timeout does not stop the
	// server handler, so a retry — or an adjacent mutating RPC — can run
	// concurrently with the abandoned call and corrupt the shared instance.
	dkgMutationMu sync.Map // map[uint32]*sync.Mutex
}

func (s *DKGServer) getInitDKGMu(round uint32) *sync.Mutex {
	v, _ := s.initDKGMu.LoadOrStore(round, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (s *DKGServer) getResharePrevMu(fromRound, toRound uint32) *sync.Mutex {
	key := uint64(fromRound)<<32 | uint64(toRound)
	v, _ := s.resharePrevMu.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (s *DKGServer) getDKGMutationMu(round uint32) *sync.Mutex {
	v, _ := s.dkgMutationMu.LoadOrStore(round, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (s *DKGServer) getReshareNextMu(round uint32) *sync.Mutex {
	v, _ := s.reshareNextMu.LoadOrStore(round, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (s *DKGServer) LoadLongtermKey(codeCommitmentHex string, round uint32) (kyber.Scalar, error) {
	return s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
}
