package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

func TestMarshalPubShare(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	t.Run("output has cb-mpc curve prefix", func(t *testing.T) {
		scalar := suite.Scalar().Pick(suite.RandomStream())
		result, err := marshalPubShare(scalar)
		require.NoError(t, err)

		require.Greater(t, len(result), 2, "result must be at least prefix + point bytes")
		assert.Equal(t, byte(sec1UncompressedPrefix), result[0], "first byte must be SEC1 uncompressed prefix 0x04")
		assert.Equal(t, byte(tdh2Edwards25519CurveID), result[1], "second byte must be TDH2 Edwards25519 curve ID 0x3f")
	})

	t.Run("point bytes follow prefix", func(t *testing.T) {
		scalar := suite.Scalar().Pick(suite.RandomStream())
		result, err := marshalPubShare(scalar)
		require.NoError(t, err)

		// Compute the expected point independently
		expectedPoint := suite.Point().Mul(scalar, nil)
		expectedBz, err := expectedPoint.MarshalBinary()
		require.NoError(t, err)

		assert.Equal(t, expectedBz, result[2:], "bytes after prefix must match raw point serialization")
		assert.Len(t, result, len(expectedBz)+2, "total length = 2 prefix bytes + point bytes")
	})

	t.Run("deterministic output", func(t *testing.T) {
		scalar := suite.Scalar().Pick(suite.RandomStream())
		r1, err1 := marshalPubShare(scalar)
		r2, err2 := marshalPubShare(scalar)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, r1, r2, "same scalar must produce identical output")
	})

	t.Run("different scalars produce different outputs", func(t *testing.T) {
		s1 := suite.Scalar().Pick(suite.RandomStream())
		s2 := suite.Scalar().Pick(suite.RandomStream())
		r1, err1 := marshalPubShare(s1)
		r2, err2 := marshalPubShare(s2)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, r1, r2, "different scalars should produce different pub shares")
	})

	t.Run("format matches buildTDH2PublicKey expectation", func(t *testing.T) {
		// Verify the output format is compatible with buildTDH2PublicKey's input format.
		// buildTDH2PublicKey prepends [0x04, 0x3f] to raw dkgPubKey bytes.
		// marshalPubShare should produce the same format directly.
		scalar := suite.Scalar().Pick(suite.RandomStream())
		result, err := marshalPubShare(scalar)
		require.NoError(t, err)

		// The raw point bytes (without prefix) should be usable with buildTDH2PublicKey
		rawPointBz := result[2:]
		manualPrefixed := append([]byte{sec1UncompressedPrefix, tdh2Edwards25519CurveID}, rawPointBz...)
		assert.Equal(t, manualPrefixed, result, "marshalPubShare output should equal manual prefix + raw point")
	})
}
