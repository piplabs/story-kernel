package integration

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/piplabs/story-kernel/config"
	"github.com/piplabs/story-kernel/service"
	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// grpcTestServer wraps a real gRPC server with a MockQueryClient for testing.
type grpcTestServer struct {
	Server  *grpc.Server
	Client  pb.KernelServiceClient
	Conn    *grpc.ClientConn
	MockQC  *MockQueryClient
	DKGSrv  *service.DKGServer
	TempDir string
}

// startTestGRPCServer creates a real gRPC server with a DKGServer registered,
// using a MockQueryClient. Returns a connected client for making RPC calls.
//
// This bypasses server.Serve() (which requires a real CometBFT light client)
// and directly assembles the gRPC server with the mock query client.
func startTestGRPCServer(t *testing.T, mockQC *MockQueryClient) *grpcTestServer {
	t.Helper()

	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SetHomeDir(dir)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	dkgSrv := &service.DKGServer{
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

	svr := grpc.NewServer(
		grpc.MaxRecvMsgSize(16*1024*1024),
		grpc.MaxSendMsgSize(16*1024*1024),
		grpc.UnaryInterceptor(testRecoveryInterceptor()),
	)
	pb.RegisterKernelServiceServer(svr, dkgSrv)

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "failed to listen on random port")

	go func() {
		if err := svr.Serve(lis); err != nil {
			// Server was stopped, this is expected during test cleanup
		}
	}()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "failed to connect to test gRPC server")

	client := pb.NewKernelServiceClient(conn)

	t.Cleanup(func() {
		conn.Close()
		svr.GracefulStop()
	})

	return &grpcTestServer{
		Server:  svr,
		Client:  client,
		Conn:    conn,
		MockQC:  mockQC,
		DKGSrv:  dkgSrv,
		TempDir: dir,
	}
}

// testRecoveryInterceptor mirrors the production recoveryInterceptor in server/server.go.
// It catches panics from handlers and converts them to codes.Internal gRPC errors.
func testRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = status.Errorf(codes.Internal, "panic recovered: %v", r)
			}
		}()
		return handler(ctx, req)
	}
}
