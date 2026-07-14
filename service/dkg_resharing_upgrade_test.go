package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"github.com/piplabs/story-kernel/store"
	"github.com/piplabs/story-kernel/story"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// upgradePlaintextSealer stores key material as plaintext; the store package's
// own plaintext sealer is unexported, so we provide an equivalent here.
type upgradePlaintextSealer struct{}

func (upgradePlaintextSealer) SealToFile(data []byte, path string) error {
	return os.WriteFile(path, data, 0o600)
}

func (upgradePlaintextSealer) UnsealFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// upgradeStubQC serves a fixed latest-active network and registration set,
// which is all the resharing build path queries.
type upgradeStubQC struct {
	latest *pb.DKGNetwork
	regs   []*pb.DKGRegistration
}

var _ story.QueryClient = (*upgradeStubQC)(nil)

func (q *upgradeStubQC) GetLatestActiveDKGNetwork(context.Context) (*pb.DKGNetwork, error) {
	return q.latest, nil
}

func (q *upgradeStubQC) GetAllParticipantDKGRegistrations(context.Context, string, uint32) ([]*pb.DKGRegistration, error) {
	return q.regs, nil
}

func (q *upgradeStubQC) GetAllRegisteredDKGRegistrations(context.Context, string, uint32) ([]*pb.DKGRegistration, error) {
	return q.regs, nil
}

func (q *upgradeStubQC) GetDKGNetwork(context.Context, string, uint32) (*pb.DKGNetwork, error) {
	return q.latest, nil
}

func (q *upgradeStubQC) HasDecryptRequest(context.Context, uint32, string, string, string) (bool, error) {
	return false, nil
}

func (q *upgradeStubQC) VerifyStartBlock(context.Context, int64, []byte) error { return nil }

func (q *upgradeStubQC) Close() error { return nil }

// TestGetResharingNextDKG_PersistsPrevStateForRestartRebuild covers a new-only
// joiner (node D below) receiving a resharing round — the general case, of which
// a fresh code commitment after a kernel upgrade is one instance. The build path
// must persist the prev-round state so the store is self-contained; without it a
// restart leaves rebuildResharingNextDKG with no prev round and DKG deadlocks.
func TestGetResharingNextDKG_PersistsPrevStateForRestartRebuild(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		cc        = "cc-upgrade"
		prevRound = uint32(10)
		toRound   = uint32(14)
		prevT     = uint32(2)
		nextT     = uint32(2)
	)

	point := func(seed int64) kyber.Point {
		return suite.Point().Mul(suite.Scalar().SetInt64(seed), nil)
	}

	// Prev committee public material. NewDistKeyHandler wraps PublicCoeffs in a
	// PubPoly without verifying them at construction, so arbitrary valid points
	// of length prevT are enough to exercise the build and rebuild paths.
	prevPubs := []kyber.Point{point(11), point(12), point(13)}
	regs := make([]*pb.DKGRegistration, len(prevPubs))
	for i, p := range prevPubs {
		bz, err := p.MarshalBinary()
		require.NoError(t, err)
		regs[i] = &pb.DKGRegistration{Index: uint32(i), Round: prevRound, DkgPubKey: bz}
	}

	coeffs := []kyber.Point{point(101), point(102)} // len == prevT
	coeffsBz, err := MarshalPoints(coeffs)
	require.NoError(t, err)

	// This node joins the next committee as a brand-new member.
	dScalar := suite.Scalar().SetInt64(777)
	dBz, err := dScalar.MarshalBinary()
	require.NoError(t, err)
	nextPubs := []kyber.Point{suite.Point().Mul(dScalar, nil), point(21), point(22)}

	dir := t.TempDir()
	st := store.NewDKGStoreWithSealer(
		filepath.Join(dir, "keys"),
		filepath.Join(dir, "state"),
		suite,
		upgradePlaintextSealer{},
	)
	require.NoError(t, st.SealAndStoreEd25519Key(cc, toRound, dBz))

	s := &DKGServer{
		QueryClient: &upgradeStubQC{
			latest: &pb.DKGNetwork{Round: prevRound, Threshold: prevT, PublicCoeffs: coeffsBz},
			regs:   regs,
		},
		Suite:              suite,
		DKGStore:           st,
		ResharingNextCache: store.NewDKGCache(),
	}

	// Cold cache + fresh store forces the build branch.
	dkgInst, err := s.GetResharingNextDKG(cc, toRound, nextT, nextPubs)
	require.NoError(t, err)
	require.NotNil(t, dkgInst)

	// Load-bearing regression signal: without the fix HasDKGState stays false.
	hasPrev, err := st.HasDKGState(cc, prevRound)
	require.NoError(t, err)
	require.True(t, hasPrev, "build path must persist the prev round state")

	prevState, err := st.LoadDKGState(cc, prevRound)
	require.NoError(t, err)
	require.Equal(t, prevT, prevState.Threshold)
	require.Len(t, prevState.PubKeys, len(prevPubs))
	require.Len(t, prevState.PublicCoeffs, len(coeffs))

	// Restart: drop the cache and rebuild the round from the store alone.
	s.ResharingNextCache = store.NewDKGCache()
	rebuilt, err := s.rebuildResharingNextDKG(cc, toRound)
	require.NoError(t, err, "rebuild after restart must not fail")
	require.NotNil(t, rebuilt)

	// Handler-level check: without the prev state kyber builds a non-resharing
	// handler where this new-only node is a dealer (Deals() returns deals). The
	// correct resharing receiver has canIssue==false, so Deals() is empty.
	deals, err := rebuilt.Deals()
	require.NoError(t, err)
	require.Empty(t, deals, "rebuilt handler must be a resharing receiver, not a fresh-DKG dealer")
}
