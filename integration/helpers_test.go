package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/curve"
	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// DKGTestCluster manages N DKGServer instances for integration testing.
type DKGTestCluster struct {
	t         *testing.T
	Servers   []*service.DKGServer
	MockQC    *MockQueryClient
	Addresses []string

	CodeCommitment []byte
	Round          uint32
	Threshold      uint32
	TempDirs       []string

	// Results from each phase
	KeyResponses   []*pb.GenerateAndSealKeyResponse
	DealResponses  []*pb.GenerateDealsResponse
	ProcessedResps [][]*pb.Response // [nodeIdx][responses]
	FinalizeResps  []*pb.FinalizeDKGResponse
}

// NewDKGTestCluster creates N DKGServer instances sharing a single MockQueryClient.
func NewDKGTestCluster(t *testing.T, numNodes int, threshold uint32) *DKGTestCluster {
	t.Helper()

	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err, "GetSelfCodeCommitment failed — must run in SGX environment")

	network := &pb.DKGNetwork{
		CodeCommitment:   codeCommitment,
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            uint32(numNodes),
		Threshold:        threshold,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}
	mockQC := NewMockQueryClient(network)

	cluster := &DKGTestCluster{
		t:              t,
		MockQC:         mockQC,
		CodeCommitment: codeCommitment,
		Round:          1,
		Threshold:      threshold,
	}

	for i := range numNodes {
		dir, err := os.MkdirTemp("", fmt.Sprintf("dkg-node-%d-*", i))
		require.NoError(t, err)
		cluster.TempDirs = append(cluster.TempDirs, dir)

		cfg := config.DefaultConfig()
		cfg.SetHomeDir(dir)

		// Each server gets its own suite — kyber suite holds mutable internal state
		// and must not be shared across concurrent DKG operations.
		suite := edwards25519.NewBlakeSHA256Ed25519()
		srv := &service.DKGServer{
			Cfg:                cfg,
			QueryClient:        mockQC,
			Suite:              suite,
			RoundCtxCache:      store.NewRoundContextCache(),
			InitDKGCache:       store.NewDKGCache(),
			ResharingPrevCache: store.NewResharingDKGCache(),
			ResharingNextCache: store.NewDKGCache(),
			DistKeyShareCache:  store.NewDistKeyShareCache(),
			DKGStore:           store.NewDKGStore(cfg.GetKeysDir(), cfg.GetDKGStateDir(), suite),
			PIDCache:           store.NewPIDCache(),
		}
		cluster.Servers = append(cluster.Servers, srv)
		cluster.Addresses = append(cluster.Addresses, fmt.Sprintf("%040x", i+1))
	}

	return cluster
}

// Cleanup removes all temporary directories.
func (c *DKGTestCluster) Cleanup() {
	for _, dir := range c.TempDirs {
		os.RemoveAll(dir)
	}
}

// GenerateAllKeys calls GenerateAndSealKey on all nodes and updates MockQC registrations.
func (c *DKGTestCluster) GenerateAllKeys() {
	c.t.Helper()
	ctx := context.Background()

	c.KeyResponses = make([]*pb.GenerateAndSealKeyResponse, len(c.Servers))
	for i, srv := range c.Servers {
		resp, err := srv.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: c.CodeCommitment,
			Round:          c.Round,
			Address:        c.Addresses[i],
		})
		require.NoError(c.t, err, "GenerateAndSealKey failed for node %d", i)
		require.NotNil(c.t, resp)
		c.KeyResponses[i] = resp
	}

	// Build registrations from key responses (1-based Index)
	regs := make([]*pb.DKGRegistration, len(c.Servers))
	for i, resp := range c.KeyResponses {
		// CommPubKey from GenerateAndSealKeyResponse is 64 bytes (raw X||Y, no prefix).
		// DKGRegistration.CommPubKey requires the 65-byte uncompressed form (0x04 prefix).
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:          c.Round,
			ValidatorAddr:  c.Addresses[i],
			Index:          uint32(i + 1), // 1-based
			DkgPubKey:      resp.GetDkgPubKey(),
			CommPubKey:     commPubKey65,
			Status:         pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	c.MockQC.SetRegistrations(regs)

	// Reset each server's RoundCtxCache to force fresh fetch with new registrations
	for _, srv := range c.Servers {
		srv.RoundCtxCache = store.NewRoundContextCache()
	}
}

// GenerateAllDeals calls GenerateDeals on all nodes.
func (c *DKGTestCluster) GenerateAllDeals() {
	c.t.Helper()
	ctx := context.Background()

	c.DealResponses = make([]*pb.GenerateDealsResponse, len(c.Servers))
	for i, srv := range c.Servers {
		resp, err := srv.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: c.CodeCommitment,
			Round:          c.Round,
		})
		require.NoError(c.t, err, "GenerateDeals failed for node %d", i)
		require.NotNil(c.t, resp)
		c.DealResponses[i] = resp
	}
}

// ProcessAllDeals routes each deal to its recipient node and collects responses.
func (c *DKGTestCluster) ProcessAllDeals() {
	c.t.Helper()
	ctx := context.Background()

	n := len(c.Servers)
	// Collect deals per recipient
	dealsByRecipient := make([][]*pb.Deal, n)
	for _, dealResp := range c.DealResponses {
		for _, deal := range dealResp.GetDeals() {
			idx := int(deal.GetRecipientIndex())
			dealsByRecipient[idx] = append(dealsByRecipient[idx], deal)
		}
	}

	c.ProcessedResps = make([][]*pb.Response, n)
	for i, srv := range c.Servers {
		resp, err := srv.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: c.CodeCommitment,
			Round:          c.Round,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(c.t, err, "ProcessDeals failed for node %d", i)
		c.ProcessedResps[i] = resp.GetResponses()
	}
}

// ProcessAllResponses broadcasts all collected responses to all nodes.
func (c *DKGTestCluster) ProcessAllResponses() {
	c.t.Helper()
	ctx := context.Background()

	// Flatten all responses
	var allResps []*pb.Response
	for _, resps := range c.ProcessedResps {
		allResps = append(allResps, resps...)
	}

	for _, srv := range c.Servers {
		_, err := srv.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: c.CodeCommitment,
			Round:          c.Round,
			Responses:      allResps,
		})
		require.NoError(c.t, err, "ProcessResponses failed")
	}
}

// FinalizeAll calls FinalizeDKG on all nodes.
func (c *DKGTestCluster) FinalizeAll() {
	c.t.Helper()
	ctx := context.Background()

	c.FinalizeResps = make([]*pb.FinalizeDKGResponse, len(c.Servers))
	for i, srv := range c.Servers {
		resp, err := srv.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: c.CodeCommitment,
			Round:          c.Round,
		})
		require.NoError(c.t, err, "FinalizeDKG failed for node %d", i)
		require.NotNil(c.t, resp)
		c.FinalizeResps[i] = resp
	}
}

// RunFullDKG executes the complete DKG flow: GenerateKeys → Deals → ProcessDeals → ProcessResponses → Finalize.
func (c *DKGTestCluster) RunFullDKG() {
	c.t.Helper()
	c.GenerateAllKeys()
	c.GenerateAllDeals()
	c.ProcessAllDeals()
	c.ProcessAllResponses()
	c.FinalizeAll()
}

// NodeName returns a stable name for node i used in TDH2 AccessStructure leaves.
func NodeName(i int) string {
	return fmt.Sprintf("node-%d", i)
}

// decryptPartialFromRequester is the inverse of encryptPartialToRequester.
// Duplicated here from service package (package-private there).
func decryptPartialFromRequester(requesterPrivKey *ecdsa.PrivateKey, ephemeralPubKey []byte, encrypted []byte) ([]byte, error) {
	ephPub, err := ecrypto.UnmarshalPubkey(ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	requesterECIES := ecies.ImportECDSA(requesterPrivKey)
	ephemeralECIES := ecies.ImportECDSAPublic(ephPub)
	sharedBytes, err := requesterECIES.GenerateShared(ephemeralECIES, 32, 0)
	if err != nil {
		return nil, err
	}

	h := hkdf.New(sha256.New, sharedBytes, nil, []byte("dkg-tdh2-partial"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(h, aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if plain == nil {
		return []byte{}, nil
	}

	return plain, nil
}

// verifyFinalizationSignature checks the signature from FinalizeDKGResponse.
// Duplicated from service package test helpers.
func verifyFinalizationSignature(commPubKey []byte, round uint32, codeCommitment [32]byte, participantsRoot [32]byte, globalPubKey []byte, publicCoeffs [][]byte, pubKeyShare []byte, signature []byte) bool {
	encoded := append([]byte{}, codeCommitment[:]...)
	encoded = append(encoded, uint32ToBytes(round)...)
	encoded = append(encoded, participantsRoot[:]...)
	encoded = append(encoded, globalPubKey...)
	for _, coeff := range publicCoeffs {
		encoded = append(encoded, coeff...)
	}
	encoded = append(encoded, pubKeyShare...)

	msgHash := ecrypto.Keccak256(encoded)
	ethMsgHash := toEthSignedMessageHash(msgHash)

	// Normalize Ethereum v-value (27/28 -> 0/1) for SigToPub.
	sig := make([]byte, len(signature))
	copy(sig, signature)
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	pubKey, err := ecrypto.SigToPub(ethMsgHash, sig)
	if err != nil {
		return false
	}

	recoveredAddr := ecrypto.PubkeyToAddress(*pubKey)
	commAddr := ecrypto.PubkeyToAddress(*mustPubKeyFromBytes(commPubKey))
	return bytes.Equal(recoveredAddr.Bytes(), commAddr.Bytes())
}

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func toEthSignedMessageHash(msgHash []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msgHash))
	return ecrypto.Keccak256([]byte(prefix), msgHash)
}

func mustPubKeyFromBytes(pubKeyBytes []byte) *ecdsa.PublicKey {
	pubKey, err := ecrypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		panic(err)
	}
	return pubKey
}

// buildTDH2AccessStructure creates a threshold AccessStructure for TDH2 combining.
// Names must match those used when collecting partial decryptions (nodeNames[i] -> PID i+1).
func buildTDH2AccessStructure(threshold int, nodeNames []string) (*mpc.AccessStructure, error) {
	ed25519Curve, err := curve.NewEd25519()
	if err != nil {
		return nil, fmt.Errorf("failed to get Ed25519 curve: %w", err)
	}

	leaves := make([]*mpc.AccessNode, len(nodeNames))
	for i, name := range nodeNames {
		pid := i + 1 // 1-based PID matching CachePID
		leaves[i] = mpc.LeafWithPID(name, pid)
	}

	root := mpc.Threshold("", threshold, leaves...)
	return &mpc.AccessStructure{Root: root, Curve: ed25519Curve}, nil
}
