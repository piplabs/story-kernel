package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v4/share/vss/pedersen"
)

// =============================================================================
// encodePubKey / decodePubKey round-trip tests
// =============================================================================

// TestEncodePubKey_RoundTrip verifies that encoding and decoding a public key
// produces the same point.
func TestEncodePubKey_RoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(priv, nil)

	encoded, err := store.encodePubKey(pub)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	decoded, err := store.decodePubKey(encoded)
	require.NoError(t, err)
	require.True(t, pub.Equal(decoded), "decoded point should equal original")
}

// TestEncodePubKey_BasePoint verifies encoding of the group generator point.
func TestEncodePubKey_BasePoint(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	base := suite.Point().Base()
	encoded, err := store.encodePubKey(base)
	require.NoError(t, err)

	decoded, err := store.decodePubKey(encoded)
	require.NoError(t, err)
	require.True(t, base.Equal(decoded))
}

// TestEncodePubKey_NullPoint verifies encoding of the identity (null) point.
func TestEncodePubKey_NullPoint(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	null := suite.Point().Null()
	encoded, err := store.encodePubKey(null)
	require.NoError(t, err)

	decoded, err := store.decodePubKey(encoded)
	require.NoError(t, err)
	require.True(t, null.Equal(decoded))
}

// TestDecodePubKey_InvalidBase64 verifies error on invalid base64 input.
func TestDecodePubKey_InvalidBase64_Extended(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	_, err := store.decodePubKey("!!!invalid!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode base64")
}

// TestDecodePubKey_TruncatedBytes verifies error on valid base64 but wrong-length point data.
func TestDecodePubKey_TruncatedBytes(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	// Base64 of a single byte - not a valid Ed25519 point
	_, err := store.decodePubKey("AQ==")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal point")
}

// =============================================================================
// saveState / loadState additional tests
// =============================================================================

// TestSaveState_CreatesDirectory verifies that saveState creates the parent directory.
func TestSaveState_CreatesDirectory(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pub := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	st := &DKGState{
		PubKeys:   []kyber.Point{pub},
		Threshold: 2,
	}

	// Use a deep nested path that doesn't exist yet
	path := filepath.Join(store.stateDir, "deep", "nested", "state.json")
	err := store.saveState(st, path)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(path)
	require.NoError(t, err)
}

// TestLoadState_NonExistentFile returns empty state without error.
func TestLoadState_NonExistentFile(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	st, err := store.loadState("/nonexistent/path/state.json")
	require.NoError(t, err)
	require.NotNil(t, st)
	require.Zero(t, st.Threshold)
	require.Empty(t, st.PubKeys)
}

// TestSaveAndLoadState_WithDealsAndResponses verifies full round-trip of state
// with deals and responses.
func TestSaveAndLoadState_WithDealsAndResponses(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()
	cc := "fullstate"
	round := uint32(1)

	ensureStateDir(t, store, cc, round)

	priv1 := suite.Scalar().Pick(suite.RandomStream())
	pub1 := suite.Point().Mul(priv1, nil)
	priv2 := suite.Scalar().Pick(suite.RandomStream())
	pub2 := suite.Point().Mul(priv2, nil)

	dkgGen, err := dkg.NewDistKeyGenerator(suite, priv1, []kyber.Point{pub1, pub2}, 2)
	require.NoError(t, err)
	dkgGen2, err := dkg.NewDistKeyGenerator(suite, priv2, []kyber.Point{pub1, pub2}, 2)
	require.NoError(t, err)

	deals, err := dkgGen.Deals()
	require.NoError(t, err)

	var dealSlice []dkg.Deal
	for _, d := range deals {
		dealSlice = append(dealSlice, *d)
	}

	// Process deal to generate a response
	var resp *dkg.Response
	for i, d := range deals {
		if i == 1 {
			r, e := dkgGen2.ProcessDeal(d)
			require.NoError(t, e)
			resp = r
		}
	}
	require.NotNil(t, resp)

	// Build complete state
	st := &DKGState{
		PubKeys:   []kyber.Point{pub1, pub2},
		Threshold: 2,
		Deals:     dealSlice,
		Responses: []dkg.Response{*resp},
	}

	require.NoError(t, store.SaveDKGState(st, cc, round))

	loaded, err := store.LoadDKGState(cc, round)
	require.NoError(t, err)
	require.Equal(t, uint32(2), loaded.Threshold)
	require.Len(t, loaded.PubKeys, 2)
	require.Len(t, loaded.Deals, len(dealSlice))
	require.Len(t, loaded.Responses, 1)
}

// =============================================================================
// toDisk / fromDisk additional tests
// =============================================================================

// TestToDisk_MultiplePubKeys verifies that multiple public keys are correctly serialized.
func TestToDisk_MultiplePubKeys(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)
	suite := edwards25519.NewBlakeSHA256Ed25519()

	pubs := make([]kyber.Point, 5)
	for i := range pubs {
		priv := suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(priv, nil)
	}

	st := &DKGState{
		PubKeys:   pubs,
		Threshold: 3,
	}

	disk, err := store.toDisk(st)
	require.NoError(t, err)
	require.Len(t, disk.PubKeysBase64, 5)

	// Verify round-trip
	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Len(t, restored.PubKeys, 5)
	for i := range pubs {
		require.True(t, pubs[i].Equal(restored.PubKeys[i]), "pub key %d mismatch", i)
	}
}

// TestFromDisk_EmptyPubKeys verifies that empty PubKeysBase64 produces empty PubKeys.
func TestFromDisk_EmptyPubKeys(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	disk := &dkgStateDisk{
		Threshold:     2,
		PubKeysBase64: []string{},
	}

	restored, err := store.fromDisk(disk)
	require.NoError(t, err)
	require.Empty(t, restored.PubKeys)
	require.Equal(t, uint32(2), restored.Threshold)
}

// TestFromDisk_InvalidPubKeyBase64 verifies error when PubKeysBase64 has invalid base64.
func TestFromDisk_InvalidPubKeyBase64(t *testing.T) {
	t.Parallel()
	store := newTestDKGStore(t)

	disk := &dkgStateDisk{
		Threshold:     2,
		PubKeysBase64: []string{"!!!invalid!!!"},
	}

	_, err := store.fromDisk(disk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode base64")
}

// =============================================================================
// MarshalDistKeyShare / UnmarshalDistKeyShare additional tests
// =============================================================================

// TestMarshalUnmarshalDistKeyShare_ZeroCommits verifies handling of a DistKeyShare
// with zero commits.
func TestMarshalUnmarshalDistKeyShare_ZeroCommits(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	priv := suite.Scalar().Pick(suite.RandomStream())
	dks := &dkg.DistKeyShare{
		Commits: []kyber.Point{}, // empty
		Share: &share.PriShare{
			I: 0,
			V: priv,
		},
		PrivatePoly: []kyber.Scalar{},
	}

	bz, err := MarshalDistKeyShare(dks)
	require.NoError(t, err)

	decoded, err := UnmarshalDistKeyShare(bz, suite)
	require.NoError(t, err)
	require.Empty(t, decoded.Commits)
	require.Equal(t, 0, decoded.Share.I)
	require.Empty(t, decoded.PrivatePoly)
}

// TestMarshalUnmarshalDistKeyShare_MultiplePrivatePoly verifies handling of
// DistKeyShare with multiple private polynomial scalars.
func TestMarshalUnmarshalDistKeyShare_MultiplePrivatePoly(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	polyScalars := make([]kyber.Scalar, 3)
	for i := range polyScalars {
		polyScalars[i] = suite.Scalar().Pick(suite.RandomStream())
	}

	commit := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	shareVal := suite.Scalar().Pick(suite.RandomStream())

	dks := &dkg.DistKeyShare{
		Commits: []kyber.Point{commit},
		Share: &share.PriShare{
			I: 2,
			V: shareVal,
		},
		PrivatePoly: polyScalars,
	}

	bz, err := MarshalDistKeyShare(dks)
	require.NoError(t, err)

	decoded, err := UnmarshalDistKeyShare(bz, suite)
	require.NoError(t, err)
	require.Len(t, decoded.Commits, 1)
	require.Equal(t, 2, decoded.Share.I)
	require.Len(t, decoded.PrivatePoly, 3)

	// Verify each private poly scalar
	for i := range polyScalars {
		origBz, _ := polyScalars[i].MarshalBinary()
		decodedBz, _ := decoded.PrivatePoly[i].MarshalBinary()
		require.True(t, bytes.Equal(origBz, decodedBz), "privatePoly[%d] mismatch", i)
	}
}

// TestUnmarshalDistKeyShare_TruncatedAfterCommitCount verifies error when data
// is truncated after the commit count but before commit data.
func TestUnmarshalDistKeyShare_TruncatedAfterCommitCount(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Write a valid commit count of 1, but no actual commit data
	buf := new(bytes.Buffer)
	buf.Write([]byte{0, 0, 0, 1}) // numCommits = 1
	// No more data — should fail reading commit length

	_, err := UnmarshalDistKeyShare(buf.Bytes(), suite)
	require.Error(t, err)
}

// TestUnmarshalDistKeyShare_InvalidCommitPointData verifies error when commit
// point data is not a valid Ed25519 point.
func TestUnmarshalDistKeyShare_InvalidCommitPointData(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	buf := new(bytes.Buffer)
	buf.Write([]byte{0, 0, 0, 1})       // numCommits = 1
	buf.Write([]byte{0, 0, 0, 3})       // commit length = 3
	buf.Write([]byte{0xFF, 0xFF, 0xFF}) // invalid point data

	_, err := UnmarshalDistKeyShare(buf.Bytes(), suite)
	require.Error(t, err)
}

// =============================================================================
// justificationsToDisk / justificationsFromDisk additional tests
// =============================================================================

// TestJustificationsToDisk_NilSecShare verifies error on nil SecShare inside Deal.
func TestJustificationsToDisk_NilSecShare(t *testing.T) {
	t.Parallel()

	badJust := dkg.Justification{
		Index: 0,
		Justification: &vss.Justification{
			Deal: &vss.Deal{
				SecShare: nil, // nil sec share
			},
		},
	}

	_, err := justificationsToDisk([]dkg.Justification{badJust})
	require.ErrorContains(t, err, "nil inner fields")
}

// TestJustificationsFromDisk_InvalidScalar verifies error on invalid scalar bytes.
func TestJustificationsFromDisk_InvalidScalar(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	disks := []justificationDisk{
		{
			Index:     0,
			SessionID: []byte("s"),
			VSSIndex:  0,
			Deal: justificationDealDisk{
				SessionID:   []byte("ds"),
				SecShareI:   0,
				SecShareV:   []byte("invalid_scalar_bytes"),
				T:           2,
				Commitments: [][]byte{},
			},
			Signature: []byte("sig"),
		},
	}

	_, err := justificationsFromDisk(suite, disks)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal justification")
}

// TestJustificationsFromDisk_InvalidCommitment verifies error on invalid commitment bytes.
func TestJustificationsFromDisk_InvalidCommitment(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create a valid scalar for SecShareV
	scalar := suite.Scalar().Pick(suite.RandomStream())
	scalarBz, err := scalar.MarshalBinary()
	require.NoError(t, err)

	disks := []justificationDisk{
		{
			Index:     0,
			SessionID: []byte("s"),
			VSSIndex:  0,
			Deal: justificationDealDisk{
				SessionID:   []byte("ds"),
				SecShareI:   0,
				SecShareV:   scalarBz,
				T:           2,
				Commitments: [][]byte{[]byte("invalid_point_bytes")},
			},
			Signature: []byte("sig"),
		},
	}

	_, err = justificationsFromDisk(suite, disks)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal justification")
}

// TestJustificationsFromDisk_Empty verifies that empty disk slice returns nil.
func TestJustificationsFromDisk_Empty(t *testing.T) {
	t.Parallel()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	result, err := justificationsFromDisk(suite, []justificationDisk{})
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestJustificationsToDisk_Empty verifies that empty justification slice returns nil.
func TestJustificationsToDisk_Empty(t *testing.T) {
	t.Parallel()

	result, err := justificationsToDisk([]dkg.Justification{})
	require.NoError(t, err)
	require.Nil(t, result)
}
