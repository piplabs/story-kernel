package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/protobuf"
	"golang.org/x/crypto/hkdf"

	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// vssDeal mirrors go.dedis.ch/kyber/v4/share/vss/pedersen.Deal for protobuf decoding.
// Replicated here because the original struct is package-private.
// Coupled to kyber v4.0.0-pre2 internal serialization format.
type vssDeal struct {
	SessionID   []byte
	SecShare    *share.PriShare
	T           uint32
	Commitments []kyber.Point
}

// vssdhExchange computes the ECDH shared key (ownPrivate * remotePublic).
// Mirrors kyber vss/pedersen/dh.go:dhExchange (v4.0.0-pre2).
func vssdhExchange(suite *edwards25519.SuiteEd25519, ownPrivate kyber.Scalar, remotePublic kyber.Point) kyber.Point {
	sk := suite.Point()
	sk.Mul(ownPrivate, remotePublic)
	return sk
}

// vssNewAEAD derives an AES-GCM AEAD from the ECDH shared point and hkdf context.
// Mirrors kyber vss/pedersen/dh.go:newAEAD (v4.0.0-pre2).
func vssNewAEAD(hashFn func() hash.Hash, preSharedKey kyber.Point, ctx []byte) (cipher.AEAD, error) {
	preBuff, _ := preSharedKey.MarshalBinary()
	reader := hkdf.New(hashFn, preBuff, nil, ctx)

	sharedKey := make([]byte, 32)
	if _, err := reader.Read(sharedKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// vssContext computes the HKDF context bytes for VSS encryption.
// Mirrors kyber vss/pedersen/dh.go:context (v4.0.0-pre2).
func vssContext(suite *edwards25519.SuiteEd25519, dealer kyber.Point, verifiers []kyber.Point) []byte {
	h := suite.Hash()
	_, _ = h.Write([]byte("vss-dealer"))
	_, _ = dealer.MarshalTo(h)
	_, _ = h.Write([]byte("vss-verifiers"))
	for _, v := range verifiers {
		_, _ = v.MarshalTo(h)
	}
	return h.Sum(nil)
}

// tamperDealCipher decrypts a protobuf deal, replaces SecShare.V with a random scalar,
// re-encrypts the deal, and re-signs at the DKG level. The result is a deal that
// decrypts successfully but fails VerifyDeal (share vs commitments mismatch),
// triggering a StatusComplaint response.
//
// The VSS-level DHKey signature is unchanged (it signs only DHKey, not cipher).
// The DKG-level signature is re-computed because it covers Index||Cipher.
//
// Coupled to kyber v4.0.0-pre2 encryption/signing internals.
func tamperDealCipher(
	t *testing.T,
	suite *edwards25519.SuiteEd25519,
	deal *pb.Deal,
	recipientPrivKey kyber.Scalar,
	dealerPrivKey kyber.Scalar,
	dealerPubKey kyber.Point,
	allPubKeys []kyber.Point,
) *pb.Deal {
	t.Helper()

	enc := deal.GetDeal()

	// Unmarshal the ephemeral DH public key
	dhKey := suite.Point()
	require.NoError(t, dhKey.UnmarshalBinary(enc.GetDhKey()))

	// Compute ECDH shared secret: recipientPriv * dhKey
	pre := vssdhExchange(suite, recipientPrivKey, dhKey)

	// Compute hkdf context
	ctx := vssContext(suite, dealerPubKey, allPubKeys)

	// Derive AEAD and decrypt
	gcm, err := vssNewAEAD(suite.Hash, pre, ctx)
	require.NoError(t, err, "failed to derive AEAD for deal decryption")

	plaintext, err := gcm.Open(nil, enc.GetNonce(), enc.GetCipher(), ctx)
	require.NoError(t, err, "failed to decrypt deal cipher")

	// Decode the plaintext deal using kyber's protobuf
	d := &vssDeal{}
	constructors := make(protobuf.Constructors)
	var point kyber.Point
	var secret kyber.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return suite.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return suite.Scalar() }
	require.NoError(t, protobuf.DecodeWithConstructors(plaintext, d, constructors), "failed to decode plaintext deal")

	// Tamper: replace SecShare.V with a random scalar
	d.SecShare.V = suite.Scalar().Pick(suite.RandomStream())

	// Re-encode and re-encrypt
	newPlaintext, err := protobuf.Encode(d)
	require.NoError(t, err, "failed to encode tampered deal")

	newCipher := gcm.Seal(nil, enc.GetNonce(), newPlaintext, ctx)

	// Re-sign the DKG-level signature: schnorr.Sign(dealerPriv, Index_LE || Cipher)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], deal.GetIndex())
	signMsg := append(buf[:], newCipher...)
	newSig, err := schnorr.Sign(suite, dealerPrivKey, signMsg)
	require.NoError(t, err, "failed to re-sign tampered deal")

	return &pb.Deal{
		Index:          deal.GetIndex(),
		RecipientIndex: deal.GetRecipientIndex(),
		Deal: &pb.EncryptedDeal{
			DhKey:     enc.GetDhKey(),
			Signature: enc.GetSignature(),
			Nonce:     enc.GetNonce(),
			Cipher:    newCipher,
		},
		Signature: newSig,
	}
}

// loadNodeLongtermKey loads the sealed Ed25519 private key for a node in the cluster.
func loadNodeLongtermKey(t *testing.T, cluster *DKGTestCluster, nodeIdx int) kyber.Scalar {
	t.Helper()
	codeCommitmentHex := hex.EncodeToString(cluster.CodeCommitment)
	privKey, err := cluster.Servers[nodeIdx].DKGStore.LoadSealedEd25519Key(codeCommitmentHex, cluster.Round)
	require.NoError(t, err, "failed to load sealed Ed25519 key for node %d", nodeIdx)
	return privKey
}

// getSortedPubKeys extracts the sorted public keys from a node's round context.
func getSortedPubKeys(t *testing.T, cluster *DKGTestCluster, nodeIdx int) []kyber.Point {
	t.Helper()
	codeCommitmentHex := hex.EncodeToString(cluster.CodeCommitment)
	rc, err := cluster.Servers[nodeIdx].GetOrLoadRoundContext(codeCommitmentHex, cluster.Round)
	require.NoError(t, err, "failed to load round context for node %d", nodeIdx)
	return rc.SortedPubKeys
}

// buildTamperedDealsByRecipient groups deals by recipient and replaces the deal
// from dealerIdx→victimIdx with a tampered version that will trigger a complaint.
func buildTamperedDealsByRecipient(
	t *testing.T,
	cluster *DKGTestCluster,
	dealerIdx, victimIdx int,
) [][]*pb.Deal {
	t.Helper()

	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := len(cluster.Servers)

	recipientPrivKey := loadNodeLongtermKey(t, cluster, victimIdx)
	dealerPrivKey := loadNodeLongtermKey(t, cluster, dealerIdx)
	dealerPubKey := suite.Point().Mul(dealerPrivKey, nil)
	sortedPubKeys := getSortedPubKeys(t, cluster, 0)

	t.Logf("Tampering deal: dealer=%d → recipient=%d", dealerIdx, victimIdx)

	byRecipient := make([][]*pb.Deal, n)
	for di, dealResp := range cluster.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			require.Less(t, idx, n)

			if di == dealerIdx && idx == victimIdx {
				tampered := tamperDealCipher(t, suite, deal, recipientPrivKey, dealerPrivKey, dealerPubKey, sortedPubKeys)
				byRecipient[idx] = append(byRecipient[idx], tampered)
			} else {
				byRecipient[idx] = append(byRecipient[idx], deal)
			}
		}
	}

	return byRecipient
}

// processDealsPerNode calls ProcessDeals on each node with the given per-recipient deals.
func processDealsPerNode(
	t *testing.T,
	cluster *DKGTestCluster,
	dealsByRecipient [][]*pb.Deal,
) [][]*pb.Response {
	t.Helper()

	n := len(cluster.Servers)
	resps := make([][]*pb.Response, n)
	ctx := context.Background()

	for i, srv := range cluster.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: cluster.CodeCommitment,
			Round:          cluster.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "ProcessDeals failed for node %d", i)
		resps[i] = resp.GetResponses()
	}

	return resps
}
