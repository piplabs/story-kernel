package service

// Run these tests via:
//
//	make test                                                          # builds cb-mpc automatically
//	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh .cbmpc go test -v -run TestScalarConversion ./service/...
//	CGO_LDFLAGS_ALLOW=".*" ./scripts/go_with_cpp.sh .cbmpc go test -v -run TestPubShareConsistency ./service/...
//
// TestScalarCompatibility verifies that Kyber Ed25519 scalar serialization is
// compatible with cb-mpc's bn_t::from_bin (big-endian) when the scalar bytes
// are reversed via reverseBytes().
//
// Background
// ----------
// Kyber's edwards25519 scalar stores values as 32-byte **little-endian** arrays
// (s.v[0] is the least-significant byte). MarshalBinary() returns those bytes in
// little-endian order via mod.Int.LittleEndian().
//
// cb-mpc's bn_t::from_bin wraps OpenSSL's BN_bin2bn which treats its input as a
// **big-endian** unsigned integer.
//
// Therefore reverseBytes(kyberScalar.MarshalBinary()) should produce the correct
// big-endian representation for cb-mpc.
//
// The test additionally checks that:
//   - cb-mpc MultiplyGenerator(reversed scalar) == Kyber Mul(scalar, basePoint)
//   - Point encodings are consistent (both produce standard Ed25519 compressed
//     32-byte points — the cb-mpc serialization prepends a 2-byte prefix so the
//     test strips it before comparing)
//   - The global pubkey produced by Kyber's DistKeyShare.Public() can be verified
//     against the Lagrange interpolation of individual pubshares produced by
//     marshalPubShare(), confirming end-to-end consistency.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kyber "go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	share "go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// cbmpcPointBytes returns the raw 32-byte Ed25519 compressed point from a
// cb-mpc serialized point.  cb-mpc prepends [0x04, 0x3f] (SEC1 uncompressed
// prefix + Edwards25519 curve ID) before the 32-byte compressed payload.
// Stripping those two bytes yields the standard Ed25519 encoding that Kyber uses.
func cbmpcPointBytes(raw []byte) ([]byte, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("cb-mpc point too short: %d bytes", len(raw))
	}
	if raw[0] != sec1UncompressedPrefix || raw[1] != tdh2Edwards25519CurveID {
		return nil, fmt.Errorf(
			"unexpected cb-mpc point prefix: got [%02x %02x], want [%02x %02x]",
			raw[0], raw[1], sec1UncompressedPrefix, tdh2Edwards25519CurveID,
		)
	}
	return raw[2:], nil
}

// kyberScalarBigInt converts a Kyber scalar to a *big.Int for diagnostic purposes.
func kyberScalarBigInt(s kyber.Scalar) (*big.Int, error) {
	b, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// b is little-endian; reverse to big-endian for big.Int.SetBytes
	be := reverseBytes(b)
	return new(big.Int).SetBytes(be), nil
}

// TestScalarConversion_KnownVector verifies the reverseBytes conversion with a
// scalar value of 1 (the simplest non-trivial case).  scalar=1 means the Kyber
// MarshalBinary result is [0x01, 0x00, ..., 0x00] (32 bytes LE) and after
// reversal becomes [0x00, ..., 0x00, 0x01] (32 bytes BE).  Both libraries must
// produce the generator point G.
func TestScalarConversion_KnownVector(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// scalar = 1
	one := suite.Scalar().One()
	oneBz, err := one.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, oneBz, 32, "Kyber scalar MarshalBinary must be 32 bytes")

	// Verify little-endian: byte 0 == 1, rest == 0
	assert.Equal(t, byte(0x01), oneBz[0],
		"Kyber scalar=1: byte[0] should be 0x01 (little-endian LSB)")
	for i := 1; i < 32; i++ {
		assert.Equal(t, byte(0x00), oneBz[i],
			"Kyber scalar=1: byte[%d] should be 0x00", i)
	}

	reversed := reverseBytes(oneBz)

	// Verify big-endian after reversal: last byte == 1, rest == 0
	assert.Equal(t, byte(0x01), reversed[31],
		"reversed scalar=1: byte[31] should be 0x01 (big-endian LSB)")
	for i := 0; i < 31; i++ {
		assert.Equal(t, byte(0x00), reversed[i],
			"reversed scalar=1: byte[%d] should be 0x00", i)
	}

	// cb-mpc: 1 * G should equal the generator
	c, err := curve.NewEd25519()
	require.NoError(t, err)
	defer c.Free()

	cbmpcPoint, err := c.MultiplyGenerator(&curve.Scalar{Bytes: reversed})
	require.NoError(t, err)
	defer cbmpcPoint.Free()

	cbmpcRaw := cbmpcPoint.Bytes()
	cbmpcCompressed, err := cbmpcPointBytes(cbmpcRaw)
	require.NoError(t, err)

	// Kyber: 1 * G should equal base point
	kyberPoint := suite.Point().Mul(one, nil) // nil means G
	kyberRaw, err := kyberPoint.MarshalBinary()
	require.NoError(t, err)

	assert.Equal(t, kyberRaw, cbmpcCompressed,
		"scalar=1: Kyber basepoint and cb-mpc generator must match.\n"+
			"Kyber G:   %s\ncb-mpc G:  %s",
		hex.EncodeToString(kyberRaw), hex.EncodeToString(cbmpcCompressed))
}

// TestScalarConversion_RandomScalars generates random Kyber scalars and checks
// that for each scalar s:
//
//	cb-mpc.MultiplyGenerator(BE(s)) == Kyber.Mul(s, G)
//
// A failure here conclusively proves that reverseBytes() is insufficient (or
// incorrect) for converting Kyber scalars to cb-mpc.
func TestScalarConversion_RandomScalars(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	c, err := curve.NewEd25519()
	require.NoError(t, err)
	defer c.Free()

	const numTrials = 20
	for trial := 0; trial < numTrials; trial++ {
		t.Run(fmt.Sprintf("trial_%d", trial), func(t *testing.T) {
			kyberScalar := suite.Scalar().Pick(suite.RandomStream())

			// ---- Kyber side ----
			kyberPoint := suite.Point().Mul(kyberScalar, nil) // s * G
			kyberRaw, err := kyberPoint.MarshalBinary()
			require.NoError(t, err)

			// ---- cb-mpc side ----
			scalarBz, err := kyberScalar.MarshalBinary()
			require.NoError(t, err)

			reversed := reverseBytes(scalarBz)
			cbmpcPoint, err := c.MultiplyGenerator(&curve.Scalar{Bytes: reversed})
			require.NoError(t, err)
			defer cbmpcPoint.Free()

			cbmpcRaw := cbmpcPoint.Bytes()
			cbmpcCompressed, err := cbmpcPointBytes(cbmpcRaw)
			require.NoError(t, err)

			// ---- Comparison ----
			if !assert.Equal(t, kyberRaw, cbmpcCompressed,
				"trial %d: Kyber s*G != cb-mpc s*G\n"+
					"scalar (LE hex): %s\n"+
					"Kyber  s*G: %s\n"+
					"cb-mpc s*G: %s",
				trial,
				hex.EncodeToString(scalarBz),
				hex.EncodeToString(kyberRaw),
				hex.EncodeToString(cbmpcCompressed),
			) {
				// Print the big-endian scalar value to aid debugging
				bi, _ := kyberScalarBigInt(kyberScalar)
				t.Logf("scalar decimal: %s", bi.String())
			}
		})
	}
}

// TestScalarConversion_FixedSeedScalar tests with a deterministic scalar
// (scalar bytes set directly) so the test is fully reproducible without a
// random source.
func TestScalarConversion_FixedSeedScalar(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	c, err := curve.NewEd25519()
	require.NoError(t, err)
	defer c.Free()

	// Use a fixed known scalar: scalar = 42 (little-endian)
	// s.v = [42, 0, 0, ..., 0]
	fortyTwo := suite.Scalar().SetInt64(42)

	fortyTwoBz, err := fortyTwo.MarshalBinary()
	require.NoError(t, err)
	t.Logf("scalar=42 MarshalBinary (LE): %s", hex.EncodeToString(fortyTwoBz))

	// Kyber: 42 * G
	kyberPoint := suite.Point().Mul(fortyTwo, nil)
	kyberRaw, err := kyberPoint.MarshalBinary()
	require.NoError(t, err)
	t.Logf("Kyber 42*G: %s", hex.EncodeToString(kyberRaw))

	// cb-mpc: reversed(LE(42)) * G
	reversed := reverseBytes(fortyTwoBz)
	t.Logf("reversed scalar (BE): %s", hex.EncodeToString(reversed))

	cbmpcPoint, err := c.MultiplyGenerator(&curve.Scalar{Bytes: reversed})
	require.NoError(t, err)
	defer cbmpcPoint.Free()

	cbmpcRaw := cbmpcPoint.Bytes()
	cbmpcCompressed, err := cbmpcPointBytes(cbmpcRaw)
	require.NoError(t, err)
	t.Logf("cb-mpc 42*G: %s", hex.EncodeToString(cbmpcCompressed))

	assert.Equal(t, kyberRaw, cbmpcCompressed,
		"scalar=42: Kyber 42*G != cb-mpc 42*G\n"+
			"If this fails, reverseBytes() does NOT correctly convert Kyber LE scalars to cb-mpc BE.")
}

// TestPubShareConsistency_WithGlobalKey performs the full DKG flow
// (t-of-n in-process) and verifies that:
//
//  1. Each validator's pubKeyShare (from marshalPubShare) equals x_i * G
//     (Kyber generator multiplication by the private share scalar).
//
//  2. The Lagrange interpolation of the pubKeyShares reconstructs the global
//     public key (distKeyShare.Public()).
//
// This is the highest-level test of the bug hypothesis: if the global pubkey
// does NOT match the Lagrange interpolation of pubShares, the scalar
// conversion in marshalPubShare is wrong.
func TestPubShareConsistency_WithGlobalKey(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	const (
		n         = 3 // total validators
		threshold = 2 // minimum threshold
	)

	// Generate keypairs for each validator
	privKeys := make([]kyber.Scalar, n)
	pubKeys := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		privKeys[i] = suite.Scalar().Pick(suite.RandomStream())
		pubKeys[i] = suite.Point().Mul(privKeys[i], nil)
	}

	// Run DKG protocol
	dkgs := make([]*dkg.DistKeyGenerator, n)
	var err error
	for i := 0; i < n; i++ {
		dkgs[i], err = dkg.NewDistKeyGenerator(suite, privKeys[i], pubKeys, threshold)
		require.NoError(t, err, "validator %d: NewDistKeyGenerator failed", i)
	}

	// Round 1: Generate deals.
	// deals[sender][recipient] = *dkg.Deal
	deals := make([]map[int]*dkg.Deal, n)
	for i := 0; i < n; i++ {
		var dealErr error
		deals[i], dealErr = dkgs[i].Deals()
		require.NoError(t, dealErr, "validator %d: Deals() failed", i)
	}

	// Round 2: Each validator processes the deals it received, collecting responses.
	// allResponses[sender] holds responses produced by validator 'sender'.
	allResponses := make([][]*dkg.Response, n)
	for i := 0; i < n; i++ {
		allResponses[i] = make([]*dkg.Response, 0)
	}
	for sender := 0; sender < n; sender++ {
		for recipient, deal := range deals[sender] {
			if recipient == sender {
				continue
			}
			resp, dealErr := dkgs[recipient].ProcessDeal(deal)
			require.NoError(t, dealErr,
				"validator %d processing deal from %d: failed", recipient, sender)
			if resp != nil {
				allResponses[recipient] = append(allResponses[recipient], resp)
			}
		}
	}

	// Round 3: Broadcast responses to everyone else.
	for sender := 0; sender < n; sender++ {
		for _, resp := range allResponses[sender] {
			if resp == nil {
				continue
			}
			for i := 0; i < n; i++ {
				if i == sender {
					continue
				}
				_, _ = dkgs[i].ProcessResponse(resp)
			}
		}
	}

	// Verify all DKGs are certified
	for i := 0; i < n; i++ {
		require.True(t, dkgs[i].Certified(), "validator %d DKG not certified", i)
	}

	// Extract distributed key shares
	distShares := make([]*dkg.DistKeyShare, n)
	for i := 0; i < n; i++ {
		distShares[i], err = dkgs[i].DistKeyShare()
		require.NoError(t, err, "validator %d: DistKeyShare() failed", i)
	}

	// All validators must agree on the global public key
	globalPubKeyBz, err := distShares[0].Public().MarshalBinary()
	require.NoError(t, err)
	t.Logf("Global public key (Kyber): %s", hex.EncodeToString(globalPubKeyBz))
	for i := 1; i < n; i++ {
		pBz, err := distShares[i].Public().MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, globalPubKeyBz, pBz,
			"validators %d and 0 disagree on global public key", i)
	}

	// ---- Core check ----
	// For each validator, compute pubKeyShare two ways:
	//   A) Kyber:   x_i * G (directly)
	//   B) cb-mpc:  marshalPubShare(x_i) — which uses reverseBytes + MultiplyGenerator
	//
	// They must match.  If they do not match, reverseBytes() is wrong.
	t.Run("per-validator pubKeyShare: Kyber vs cb-mpc", func(t *testing.T) {
		for i := 0; i < n; i++ {
			priShare := distShares[i].PriShare()
			require.NotNil(t, priShare)

			// Method A: Kyber multiplication
			kyberPubShare := suite.Point().Mul(priShare.V, nil)
			kyberPubShareBz, err := kyberPubShare.MarshalBinary()
			require.NoError(t, err)

			// Method B: marshalPubShare (via cb-mpc)
			cbmpcPubShareRaw, err := marshalPubShare(priShare.V)
			require.NoError(t, err)
			cbmpcPubShareBz, err := cbmpcPointBytes(cbmpcPubShareRaw)
			require.NoError(t, err)

			t.Logf("validator %d (index=%d):", i, priShare.I)
			t.Logf("  Kyber  x_i*G: %s", hex.EncodeToString(kyberPubShareBz))
			t.Logf("  cb-mpc x_i*G: %s", hex.EncodeToString(cbmpcPubShareBz))

			assert.Equal(t, kyberPubShareBz, cbmpcPubShareBz,
				"validator %d: Kyber x_i*G != cb-mpc x_i*G — reverseBytes() scalar conversion is WRONG",
				i)
		}
	})

	// ---- Lagrange check ----
	// Verify that Lagrange interpolation of pubKeyShares (in Kyber) gives the
	// global public key.  This is the same interpolation the on-chain contract
	// would perform.
	t.Run("Lagrange interpolation of Kyber pubKeyShares == globalPubKey", func(t *testing.T) {
		pubShares := make([]*share.PubShare, n)
		for i := 0; i < n; i++ {
			priShare := distShares[i].PriShare()
			pubShares[i] = &share.PubShare{
				I: priShare.I,
				V: suite.Point().Mul(priShare.V, nil),
			}
		}

		recovered, err := share.RecoverCommit(suite, pubShares, threshold, n)
		require.NoError(t, err, "Lagrange interpolation of Kyber pubShares failed")

		recoveredBz, err := recovered.MarshalBinary()
		require.NoError(t, err)

		t.Logf("Global pubkey (Kyber): %s", hex.EncodeToString(globalPubKeyBz))
		t.Logf("Lagrange recovered:    %s", hex.EncodeToString(recoveredBz))

		assert.Equal(t, globalPubKeyBz, recoveredBz,
			"Lagrange interpolation of pubKeyShares does NOT equal globalPubKey.\n"+
				"This confirms the DKG pubShare reconstruction failure observed on-chain.")
	})
}
