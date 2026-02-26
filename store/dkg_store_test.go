package store

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

func TestEncodeDecode_DistKeyShare(t *testing.T) {
	const tmpFilePath = "/tmp/dist_key_share.bin"
	defer os.Remove(tmpFilePath)

	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	distKeyGen, err := dkg.NewDistKeyGenerator(suite, priv, []kyber.Point{pub, pub2}, 2)
	if err != nil {
		t.Fatalf("failed to create DKG: %v", err)
	}

	distKeyGen2, err := dkg.NewDistKeyGenerator(suite, priv2, []kyber.Point{pub, pub2}, 2)
	if err != nil {
		t.Fatalf("failed to create DKG2: %v", err)
	}

	fullExchange(t, []*dkg.DistKeyGenerator{distKeyGen, distKeyGen2})

	dks, err := distKeyGen.DistKeyShare()
	require.NoError(t, err)

	bz, err := MarshalDistKeyShare(dks)
	require.NoError(t, err)

	err = os.WriteFile(tmpFilePath, bz, 0600)
	require.NoError(t, err)

	readBz, err := os.ReadFile(tmpFilePath)
	require.NoError(t, err)

	decoded, err := UnmarshalDistKeyShare(readBz, suite)
	require.NoError(t, err)

	require.Equal(t, len(dks.Commits), len(decoded.Commits))
	require.Equal(t, dks.Share.I, decoded.Share.I)
	require.Equal(t, len(dks.PrivatePoly), len(decoded.PrivatePoly))

	for i := range dks.Commits {
		orig, _ := dks.Commits[i].MarshalBinary()
		recon, _ := decoded.Commits[i].MarshalBinary()
		require.True(t, bytes.Equal(orig, recon), "commit[%d] not equal", i)
	}

	origShare, _ := dks.Share.V.MarshalBinary()
	reconShare, _ := decoded.Share.V.MarshalBinary()
	require.True(t, bytes.Equal(origShare, reconShare), "share value not equal")

	for i := range dks.PrivatePoly {
		orig, _ := dks.PrivatePoly[i].MarshalBinary()
		recon, _ := decoded.PrivatePoly[i].MarshalBinary()
		require.True(t, bytes.Equal(orig, recon), "privatePoly[%d] not equal", i)
	}
}

func fullExchange(t *testing.T, dkgs []*dkg.DistKeyGenerator) {
	// full secret sharing exchange
	// 1. broadcast deals
	n := len(dkgs)
	resps := make([]*dkg.Response, 0, n*n)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.NoError(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.NoError(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for i, dkg := range dkgs {
			// Ignore messages about ourselves
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.NoError(t, err)
			require.Nil(t, j)
		}
	}
}
