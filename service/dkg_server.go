package service

import "go.dedis.ch/kyber/v4"

func (s *DKGServer) LoadLongtermKey(codeCommitmentHex string, round uint32) (kyber.Scalar, error) {
	return s.DKGStore.LoadSealedEd25519Key(codeCommitmentHex, round)
}
