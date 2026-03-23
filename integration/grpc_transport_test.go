package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/piplabs/story-kernel/enclave"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"
)

// ---------- B: gRPC transport layer tests ----------

// TestGRPC_HappyPath_EndToEnd verifies a complete DKG + TDH2 flow through the gRPC
// transport layer, ensuring protobuf serialization/deserialization is lossless.
// This differs from existing tests which call DKGServer methods directly.
func TestGRPC_HappyPath_EndToEnd(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            3,
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}
	mockQC := NewMockQueryClient(network)

	// Start 3 gRPC servers
	servers := make([]*grpcTestServer, 3)
	addresses := make([]string, 3)
	for i := range 3 {
		servers[i] = startTestGRPCServer(t, mockQC)
		addresses[i] = fmt.Sprintf("%040x", i+1)
	}

	ctx := context.Background()

	// Phase 1: GenerateAndSealKey via gRPC
	keyResps := make([]*pb.GenerateAndSealKeyResponse, 3)
	for i, srv := range servers {
		resp, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
			CodeCommitment: codeCommitment,
			Round:          1,
			Address:        addresses[i],
		})
		require.NoError(t, err, "gRPC GenerateAndSealKey failed for node %d", i)
		require.NotEmpty(t, resp.GetDkgPubKey(), "DkgPubKey should not be empty")
		require.NotEmpty(t, resp.GetCommPubKey(), "CommPubKey should not be empty")
		keyResps[i] = resp
	}

	// Set registrations
	regs := make([]*pb.DKGRegistration, 3)
	for i, resp := range keyResps {
		commPubKey65 := make([]byte, 65)
		commPubKey65[0] = 0x04
		copy(commPubKey65[1:], resp.GetCommPubKey())
		regs[i] = &pb.DKGRegistration{
			Round:         1,
			ValidatorAddr: addresses[i],
			Index:         uint32(i + 1),
			DkgPubKey:     resp.GetDkgPubKey(),
			CommPubKey:    commPubKey65,
			Status:        pb.DKGRegStatus_DKG_REG_STATUS_VERIFIED,
		}
	}
	mockQC.SetRegistrations(regs)
	for _, srv := range servers {
		srv.DKGSrv.RoundCtxCache = store.NewRoundContextCache()
	}

	// Phase 2: GenerateDeals via gRPC
	dealResps := make([]*pb.GenerateDealsResponse, 3)
	for i, srv := range servers {
		resp, err := srv.Client.GenerateDeals(ctx, &pb.GenerateDealsRequest{
			CodeCommitment: codeCommitment,
			Round:          1,
		})
		require.NoError(t, err, "gRPC GenerateDeals failed for node %d", i)
		require.NotEmpty(t, resp.GetDeals(), "deals should not be empty")
		dealResps[i] = resp
	}

	// Phase 3: ProcessDeals via gRPC
	dealsByRecipient := buildDealsByRecipient(t, 3, dealResps)
	allResps := make([][]*pb.Response, 3)
	for i, srv := range servers {
		resp, err := srv.Client.ProcessDeals(ctx, &pb.ProcessDealsRequest{
			CodeCommitment: codeCommitment,
			Round:          1,
			Deals:          dealsByRecipient[i],
		})
		require.NoError(t, err, "gRPC ProcessDeals failed for node %d", i)
		allResps[i] = resp.GetResponses()
	}

	// Phase 4: ProcessResponses via gRPC
	var flatResps []*pb.Response
	for _, resps := range allResps {
		flatResps = append(flatResps, resps...)
	}
	for i, srv := range servers {
		_, err := srv.Client.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
			CodeCommitment: codeCommitment,
			Round:          1,
			Responses:      flatResps,
		})
		require.NoError(t, err, "gRPC ProcessResponses failed for node %d", i)
	}

	// Phase 5: FinalizeDKG via gRPC
	finalResps := make([]*pb.FinalizeDKGResponse, 3)
	for i, srv := range servers {
		resp, err := srv.Client.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
			CodeCommitment: codeCommitment,
			Round:          1,
		})
		require.NoError(t, err, "gRPC FinalizeDKG failed for node %d", i)
		require.NotEmpty(t, resp.GetGlobalPubKey(), "GlobalPubKey should not be empty")
		finalResps[i] = resp
	}

	// Verify all nodes agree on global public key
	for i := 1; i < 3; i++ {
		require.Equal(t,
			finalResps[0].GetGlobalPubKey(),
			finalResps[i].GetGlobalPubKey(),
			"global public key mismatch between node 0 and node %d via gRPC", i,
		)
	}

	// Phase 6: PartialDecryptTDH2 via gRPC
	globalPubKey := finalResps[0].GetGlobalPubKey()
	tdh2PubKey, err := buildTDH2PubKey(globalPubKey)
	require.NoError(t, err)
	defer tdh2PubKey.Free()

	plaintext := []byte("grpc end-to-end test data")
	label := []byte("grpc-label")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPubBytes := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// Set latest active network for PartialDecryptTDH2
	mockQC.SetLatestActiveNetwork(network)

	type partialResult struct {
		partial  *mpc.TDH2PartialDecryption
		pubShare []byte
	}

	results := make([]partialResult, 2)
	for i := 0; i < 2; i++ {
		resp, err := servers[i].Client.PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
			CodeCommitment:  codeCommitment,
			Round:           1,
			Ciphertext:      ct.Bytes,
			GlobalPubKey:    globalPubKey,
			Label:           label,
			RequesterPubKey: requesterPubBytes,
		})
		require.NoError(t, err, "gRPC PartialDecryptTDH2 failed for node %d", i)

		partialBytes, err := decryptPartialFromRequester(requesterPriv, resp.GetEphemeralPubKey(), resp.GetEncryptedPartialDecryption())
		require.NoError(t, err)
		results[i] = partialResult{
			partial:  &mpc.TDH2PartialDecryption{Bytes: partialBytes},
			pubShare: resp.GetPubShare(),
		}
	}

	// Combine and verify decryption
	nodeNames := []string{NodeName(0), NodeName(1), NodeName(2)}
	as, err := buildTDH2AccessStructure(2, nodeNames)
	require.NoError(t, err)

	pubShares := map[string][]byte{
		NodeName(0): results[0].pubShare,
		NodeName(1): results[1].pubShare,
	}
	pdMap := map[string]*mpc.TDH2PartialDecryption{
		NodeName(0): results[0].partial,
		NodeName(1): results[1].partial,
	}

	decrypted, err := mpc.TDH2Combine(as, tdh2PubKey, pubShares, ct, label, pdMap)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted, "gRPC end-to-end decryption should match original plaintext")
}

// TestGRPC_ErrorCodeMapping verifies that gRPC status codes are correctly propagated
// through the transport layer for various error scenarios.
func TestGRPC_ErrorCodeMapping(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            3,
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}
	mockQC := NewMockQueryClient(network)
	srv := startTestGRPCServer(t, mockQC)

	ctx := context.Background()

	tests := []struct {
		name         string
		call         func() error
		expectedCode codes.Code
	}{
		{
			name: "GenerateAndSealKey_ZeroRound",
			call: func() error {
				_, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
					CodeCommitment: codeCommitment,
					Round:          0,
					Address:        "0x1234",
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "GenerateAndSealKey_EmptyCodeCommitment",
			call: func() error {
				_, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
					CodeCommitment: []byte{},
					Round:          1,
					Address:        "0x1234",
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "GenerateAndSealKey_WrongCodeCommitment",
			call: func() error {
				_, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
					CodeCommitment: bytes.Repeat([]byte{0xDE}, 32),
					Round:          1,
					Address:        "0x1234",
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "GenerateDeals_ZeroRound",
			call: func() error {
				_, err := srv.Client.GenerateDeals(ctx, &pb.GenerateDealsRequest{
					CodeCommitment: codeCommitment,
					Round:          0,
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "ProcessDeals_EmptyDeals",
			call: func() error {
				_, err := srv.Client.ProcessDeals(ctx, &pb.ProcessDealsRequest{
					CodeCommitment: codeCommitment,
					Round:          1,
					Deals:          []*pb.Deal{},
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "ProcessResponses_ZeroRound",
			call: func() error {
				_, err := srv.Client.ProcessResponses(ctx, &pb.ProcessResponsesRequest{
					CodeCommitment: codeCommitment,
					Round:          0,
					Responses:      []*pb.Response{},
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "FinalizeDKG_ZeroRound",
			call: func() error {
				_, err := srv.Client.FinalizeDKG(ctx, &pb.FinalizeDKGRequest{
					CodeCommitment: codeCommitment,
					Round:          0,
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "PartialDecryptTDH2_ZeroRound",
			call: func() error {
				_, err := srv.Client.PartialDecryptTDH2(ctx, &pb.PartialDecryptTDH2Request{
					CodeCommitment: codeCommitment,
					Round:          0,
					Ciphertext:     []byte("dummy"),
					GlobalPubKey:   []byte("dummy"),
					Label:          []byte("dummy"),
				})
				return err
			},
			expectedCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err, "expected error for %s", tc.name)
			st, ok := status.FromError(err)
			require.True(t, ok, "error should be a gRPC status error")
			require.Equal(t, tc.expectedCode, st.Code(),
				"expected gRPC code %v but got %v for %s: %s",
				tc.expectedCode, st.Code(), tc.name, st.Message())
		})
	}
}

// TestGRPC_LargePayload verifies that deal data for a 5-node cluster
// can be transmitted through gRPC without exceeding message size limits.
// Uses real keys via NewDKGTestCluster so kyber can actually generate deals.
func TestGRPC_LargePayload(t *testing.T) {
	// Use a 5-node cluster with real keys to produce 4 deals per node
	cluster := NewDKGTestCluster(t, 5, 3)
	defer cluster.Cleanup()

	cluster.GenerateAllKeys()

	// Start a gRPC server that wraps node 0's DKGServer
	srv := startTestGRPCServer(t, cluster.MockQC)
	// Point the gRPC server's DKGServer at the cluster's node 0 state
	srv.DKGSrv.Cfg = cluster.Servers[0].Cfg
	srv.DKGSrv.Suite = cluster.Servers[0].Suite
	srv.DKGSrv.RoundCtxCache = cluster.Servers[0].RoundCtxCache
	srv.DKGSrv.InitDKGCache = cluster.Servers[0].InitDKGCache
	srv.DKGSrv.ResharingPrevCache = cluster.Servers[0].ResharingPrevCache
	srv.DKGSrv.ResharingNextCache = cluster.Servers[0].ResharingNextCache
	srv.DKGSrv.DistKeyShareCache = cluster.Servers[0].DistKeyShareCache
	srv.DKGSrv.DKGStore = cluster.Servers[0].DKGStore
	srv.DKGSrv.PIDCache = cluster.Servers[0].PIDCache

	ctx := context.Background()

	// GenerateDeals via gRPC — should produce 4 deals for 5 nodes
	resp, err := srv.Client.GenerateDeals(ctx, &pb.GenerateDealsRequest{
		CodeCommitment: cluster.CodeCommitment,
		Round:          cluster.Round,
	})
	require.NoError(t, err, "GenerateDeals should succeed via gRPC for 5-node cluster")
	require.NotEmpty(t, resp.GetDeals(), "deals should not be empty")
	t.Logf("GenerateDeals returned %d deals for 5-node cluster via gRPC", len(resp.GetDeals()))
}

// TestGRPC_ConcurrentClients verifies that multiple gRPC clients can concurrently
// make requests to the same server without data corruption or deadlocks.
func TestGRPC_ConcurrentClients(t *testing.T) {
	codeCommitment, err := enclave.GetSelfCodeCommitment()
	require.NoError(t, err)

	network := &pb.DKGNetwork{
		Round:            1,
		StartBlockHeight: 100,
		StartBlockHash:   bytes.Repeat([]byte{0xab}, 32),
		Total:            3,
		Threshold:        2,
		Stage:            pb.DKGStage_DKG_STAGE_DEALING,
	}
	mockQC := NewMockQueryClient(network)
	srv := startTestGRPCServer(t, mockQC)

	// Complete DKG on this server directly to set up state
	ctx := context.Background()
	keyResp, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
		CodeCommitment: codeCommitment,
		Round:          1,
		Address:        fmt.Sprintf("%040x", 1),
	})
	require.NoError(t, err)

	// 5 concurrent clients calling GetCodeCommitment
	numClients := 5
	var wg sync.WaitGroup
	errs := make([]error, numClients)
	commitments := make([][]byte, numClients)

	wg.Add(numClients)
	for i := range numClients {
		go func(idx int) {
			defer wg.Done()
			resp, err := srv.Client.GetCodeCommitment(ctx, &pb.GetCodeCommitmentRequest{})
			errs[idx] = err
			if resp != nil {
				commitments[idx] = resp.GetCodeCommitment()
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "concurrent GetCodeCommitment failed for client %d", i)
		require.Equal(t, codeCommitment, commitments[i],
			"code commitment mismatch for concurrent client %d", i)
	}

	// Verify the earlier key generation response is still valid
	require.NotEmpty(t, keyResp.GetDkgPubKey())

	// Concurrent GenerateAndSealKey calls from multiple clients, each with a different address
	numKeyClients := 5
	keyErrs := make([]error, numKeyClients)
	keyResps := make([]*pb.GenerateAndSealKeyResponse, numKeyClients)

	var keyWg sync.WaitGroup
	keyWg.Add(numKeyClients)
	for i := range numKeyClients {
		go func(idx int) {
			defer keyWg.Done()
			resp, err := srv.Client.GenerateAndSealKey(ctx, &pb.GenerateAndSealKeyRequest{
				CodeCommitment: codeCommitment,
				Round:          1,
				Address:        fmt.Sprintf("%040x", idx+100), // unique addresses
			})
			keyErrs[idx] = err
			keyResps[idx] = resp
		}(i)
	}
	keyWg.Wait()

	for i, err := range keyErrs {
		require.NoError(t, err, "concurrent GenerateAndSealKey failed for client %d", i)
		require.NotEmpty(t, keyResps[i].GetDkgPubKey(),
			"DkgPubKey should not be empty for concurrent client %d", i)
	}
}
