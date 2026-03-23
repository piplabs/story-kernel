package service

import (
	"github.com/piplabs/story-kernel/dkgutil"

	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// extractDealerPolyCoeffs delegates to dkgutil.ExtractDealerPolyCoeffs.
// See that function for full documentation.
func extractDealerPolyCoeffs(dkgInst *dkg.DistKeyGenerator, suite *edwards25519.SuiteEd25519) ([][]byte, error) {
	return dkgutil.ExtractDealerPolyCoeffs(dkgInst, suite)
}

// restoreDealerPoly delegates to dkgutil.RestoreDealerPoly.
// See that function for full documentation.
func restoreDealerPoly(suite *edwards25519.SuiteEd25519, dkgInst *dkg.DistKeyGenerator, coeffBytes [][]byte) error {
	return dkgutil.RestoreDealerPoly(suite, dkgInst, coeffBytes)
}
