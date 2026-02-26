package crypto

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

func GenerateNewEd25519Key() (kyber.Scalar, kyber.Point) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	edPriv := suite.Scalar().Pick(suite.RandomStream())
	edPub := suite.Point().Mul(edPriv, nil)

	return edPriv, edPub
}
