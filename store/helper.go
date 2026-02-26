package store

import (
	"encoding/base64"

	"github.com/pkg/errors"

	"go.dedis.ch/kyber/v4"
)

func (s *DKGStore) encodePubKey(p kyber.Point) (string, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func (s *DKGStore) decodePubKey(encoded string) (kyber.Point, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64")
	}

	p := s.suite.Point()
	if err := p.UnmarshalBinary(raw); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal point")
	}

	return p, nil
}
