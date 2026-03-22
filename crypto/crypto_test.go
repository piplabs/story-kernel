package crypto

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// TestGenerateNewEd25519Key verifies that key generation returns valid scalars and points.
func TestGenerateNewEd25519Key(t *testing.T) {
	t.Parallel()

	priv, pub := GenerateNewEd25519Key()
	require.NotNil(t, priv, "private key must not be nil")
	require.NotNil(t, pub, "public key must not be nil")

	// Verify the public key is the scalar multiplication of the private key.
	suite := edwards25519.NewBlakeSHA256Ed25519()
	expectedPub := suite.Point().Mul(priv, nil)
	require.True(t, expectedPub.Equal(pub), "pub must be G*priv")
}

// TestGenerateNewEd25519Key_Uniqueness verifies that two calls produce different keys.
func TestGenerateNewEd25519Key_Uniqueness(t *testing.T) {
	t.Parallel()

	priv1, _ := GenerateNewEd25519Key()
	priv2, _ := GenerateNewEd25519Key()

	b1, err := priv1.MarshalBinary()
	require.NoError(t, err)
	b2, err := priv2.MarshalBinary()
	require.NoError(t, err)

	require.NotEqual(t, b1, b2, "two generated keys should not be equal")
}

// TestGenerateNewEd25519Key_MarshalRoundTrip verifies that the private key
// can be marshalled and unmarshalled without loss.
func TestGenerateNewEd25519Key_MarshalRoundTrip(t *testing.T) {
	t.Parallel()

	priv, _ := GenerateNewEd25519Key()
	suite := edwards25519.NewBlakeSHA256Ed25519()

	bz, err := priv.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, bz)

	restored := suite.Scalar()
	require.NoError(t, restored.UnmarshalBinary(bz))

	// Verify that the restored key produces the same public key.
	origPub := suite.Point().Mul(priv, nil)
	restoredPub := suite.Point().Mul(restored, nil)
	require.True(t, origPub.Equal(restoredPub), "restored key should produce the same public key")
}

// TestGenerateNewSecp256k1Key verifies that key generation returns valid ECDSA keys.
func TestGenerateNewSecp256k1Key(t *testing.T) {
	t.Parallel()

	priv, pub, err := GenerateNewSecp256k1Key()
	require.NoError(t, err)
	require.NotNil(t, priv, "private key must not be nil")
	require.NotNil(t, pub, "public key must not be nil")

	// Verify the public key is derived from the private key.
	derivedPub, ok := priv.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, derivedPub.Equal(pub), "public key must match the private key's public component")
}

// TestGenerateNewSecp256k1Key_Uniqueness verifies that two calls produce different keys.
func TestGenerateNewSecp256k1Key_Uniqueness(t *testing.T) {
	t.Parallel()

	priv1, _, err1 := GenerateNewSecp256k1Key()
	require.NoError(t, err1)
	priv2, _, err2 := GenerateNewSecp256k1Key()
	require.NoError(t, err2)

	require.False(t, priv1.D.Cmp(priv2.D) == 0, "two generated keys should have different private values")
}

// TestGenerateNewSecp256k1Key_PublicKeyIsValid verifies the X and Y coordinates are set.
func TestGenerateNewSecp256k1Key_PublicKeyIsValid(t *testing.T) {
	t.Parallel()

	_, pub, err := GenerateNewSecp256k1Key()
	require.NoError(t, err)
	require.NotNil(t, pub.X, "X coordinate must not be nil")
	require.NotNil(t, pub.Y, "Y coordinate must not be nil")
}

// TestGenerateNewSecp256k1Key_KeyIsOnCurve verifies the public key lies on secp256k1.
func TestGenerateNewSecp256k1Key_KeyIsOnCurve(t *testing.T) {
	t.Parallel()

	_, pub, err := GenerateNewSecp256k1Key()
	require.NoError(t, err)
	require.True(t, pub.Curve.IsOnCurve(pub.X, pub.Y), "public key must be on the secp256k1 curve")
}

// TestGenerateNewSecp256k1Key_PrivateKeyConsistency verifies that the public key
// matches the private key's public component via the Public() method.
func TestGenerateNewSecp256k1Key_PrivateKeyConsistency(t *testing.T) {
	t.Parallel()

	priv, pub, err := GenerateNewSecp256k1Key()
	require.NoError(t, err)

	derivedPub, ok := priv.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "Public() must return *ecdsa.PublicKey")
	require.True(t, pub.Equal(derivedPub), "returned public key must match derived")
}

// TestGenerateNewSecp256k1Key_PrivateKeyNonZero verifies the private key scalar is non-zero.
func TestGenerateNewSecp256k1Key_PrivateKeyNonZero(t *testing.T) {
	t.Parallel()

	priv, _, err := GenerateNewSecp256k1Key()
	require.NoError(t, err)
	require.NotZero(t, priv.D.Sign(), "private key scalar must be non-zero")
}

// TestGenerateNewSecp256k1Key_MultipleCalls verifies that multiple sequential
// calls all succeed and produce distinct keys.
func TestGenerateNewSecp256k1Key_MultipleCalls(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for range 10 {
		priv, _, err := GenerateNewSecp256k1Key()
		require.NoError(t, err)
		dBytes := priv.D.Bytes()
		key := string(dBytes)
		require.False(t, seen[key], "generated duplicate key")
		seen[key] = true
	}
}
