package service

import (
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
}

func (s *DKGServer) LoadLongtermKey(codeCommitmentHex string, round uint32) (kyber.Scalar, error) {
	return s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
}
