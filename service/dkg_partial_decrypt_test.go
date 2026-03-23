package service

import (
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
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

	t.Run("matches cb-mpc MultiplyGenerator output", func(t *testing.T) {
		scalar := suite.Scalar().Pick(suite.RandomStream())
		result, err := marshalPubShare(scalar)
		require.NoError(t, err)

		// Independently compute via cb-mpc to verify consistency
		shareBz, err := scalar.MarshalBinary()
		require.NoError(t, err)

		c, err := curve.NewEd25519()
		require.NoError(t, err)
		defer c.Free()

		s := &curve.Scalar{Bytes: reverseBytes(shareBz)}
		point, err := c.MultiplyGenerator(s)
		require.NoError(t, err)
		defer point.Free()

		assert.Equal(t, point.Bytes(), result, "marshalPubShare must match cb-mpc MultiplyGenerator")
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
}
