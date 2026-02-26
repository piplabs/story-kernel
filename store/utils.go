package store

import (
	"bytes"
	"encoding/binary"
	"io"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

func MarshalDistKeyShare(dist *dkg.DistKeyShare) ([]byte, error) {
	buf := new(bytes.Buffer)

	numCommits := uint32(len(dist.Commits))
	if err := binary.Write(buf, binary.BigEndian, numCommits); err != nil {
		return nil, err
	}
	for _, pt := range dist.Commits {
		b, err := pt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, uint32(len(b))); err != nil {
			return nil, err
		}
		buf.Write(b)
	}

	if err := binary.Write(buf, binary.BigEndian, int32(dist.Share.I)); err != nil {
		return nil, err
	}

	shareBytes, err := dist.Share.V.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, uint32(len(shareBytes))); err != nil {
		return nil, err
	}
	buf.Write(shareBytes)

	numPriv := uint32(len(dist.PrivatePoly))
	if err := binary.Write(buf, binary.BigEndian, numPriv); err != nil {
		return nil, err
	}

	for _, sc := range dist.PrivatePoly {
		b, err := sc.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, uint32(len(b))); err != nil {
			return nil, err
		}
		buf.Write(b)
	}

	return buf.Bytes(), nil
}

func UnmarshalDistKeyShare(data []byte, suite kyber.Group) (*dkg.DistKeyShare, error) {
	buf := bytes.NewReader(data)
	dist := &dkg.DistKeyShare{}

	var numCommits uint32
	if err := binary.Read(buf, binary.BigEndian, &numCommits); err != nil {
		return nil, err
	}

	for range numCommits {
		var l uint32
		if err := binary.Read(buf, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(buf, b); err != nil {
			return nil, err
		}
		pt := suite.Point()
		if err := pt.UnmarshalBinary(b); err != nil {
			return nil, err
		}
		dist.Commits = append(dist.Commits, pt)
	}

	var index int32
	if err := binary.Read(buf, binary.BigEndian, &index); err != nil {
		return nil, err
	}

	var l uint32
	if err := binary.Read(buf, binary.BigEndian, &l); err != nil {
		return nil, err
	}

	b := make([]byte, l)
	if _, err := io.ReadFull(buf, b); err != nil {
		return nil, err
	}

	sc := suite.Scalar()
	if err := sc.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	dist.Share = &share.PriShare{I: int(index), V: sc}

	var numPriv uint32
	if err := binary.Read(buf, binary.BigEndian, &numPriv); err != nil {
		return nil, err
	}

	for range numPriv {
		var l uint32
		if err := binary.Read(buf, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(buf, b); err != nil {
			return nil, err
		}
		sc := suite.Scalar()
		if err := sc.UnmarshalBinary(b); err != nil {
			return nil, err
		}
		dist.PrivatePoly = append(dist.PrivatePoly, sc)
	}

	return dist, nil
}
