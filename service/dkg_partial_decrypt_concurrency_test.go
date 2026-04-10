package service

// Build and run:
//
//	CXX_INC=/Library/Developer/CommandLineTools/SDKs/MacOSX26.4.sdk/usr/include/c++/v1 \
//	CPLUS_INCLUDE_PATH="${CXX_INC}" \
//	CGO_LDFLAGS_ALLOW=".*" \
//	./scripts/go_with_cpp.sh .cbmpc go test \
//	  -v -count=1 -timeout=120s ./service/
//
// Direct go test will fail because the cb-mpc C++ library (libcbmpc.a) and its
// headers are not on the default search path. go_with_cpp.sh builds the library
// if needed and sets CGO_CFLAGS / CGO_CXXFLAGS / CGO_LDFLAGS accordingly.
// CPLUS_INCLUDE_PATH is required because the active clang on this machine
// defaults to a MacOSX26.2.sdk path that does not exist; pointing it at
// MacOSX26.4.sdk makes the C++ standard-library headers (memory, iostream, …)
// resolvable.

// Concurrency tests for PartialDecryptTDH2.
//
// TestPartialDecryptTDH2Concurrent
//   Tests the full RPC handler under concurrent load.
//   The ValidateCodeCommitment check is bypassed via DKGServer.ValidateCodeCommitment
//   so that every goroutine reaches the TDH2 crypto path and returns a valid
//   response regardless of SGX availability.
//
// TestTDH2AllPartiesConcurrent
//   Each of the n=5 parties performs its partial decryption in a separate
//   goroutine. After all finish the threshold partial decryptions are
//   combined to recover the plaintext, verifying end-to-end correctness
//   under concurrent execution.
//
// TestTDH2SinglePartyConcurrent
//   100 goroutines all call mpc.TDH2PartialDecrypt + encryptPartialToRequester
//   with the same shared party-1 objects to stress-test the CGO library's
//   thread safety and measure throughput.
//
// BenchmarkTDH2PartialDecryptSerial / BenchmarkTDH2PartialDecryptParallel
//   Baseline and concurrent throughput benchmarks for the core crypto op.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mpc "github.com/coinbase/cb-mpc/demos-go/cb-mpc-go/api/mpc"
	ecrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/store"
	pb "github.com/piplabs/story-kernel/types/pb/v0"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// ─── test infrastructure ────────────────────────────────────────────────────

// concurrencyTestSealer writes/reads data as plaintext (no SGX required).
type concurrencyTestSealer struct{}

func (concurrencyTestSealer) SealToFile(data []byte, path string) error {
	return os.WriteFile(path, data, 0o600)
}

func (concurrencyTestSealer) UnsealFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// concurrencyTestQueryClient satisfies story.QueryClient for concurrent tests.
// HasDecryptRequest always returns true so the existence check in
// validatePartialDecryptTDH2Request passes without hitting the chain.
type concurrencyTestQueryClient struct {
	network *pb.DKGNetwork
}

func (m *concurrencyTestQueryClient) GetDKGNetwork(_ context.Context, _ string, _ uint32) (*pb.DKGNetwork, error) {
	return m.network, nil
}

func (m *concurrencyTestQueryClient) GetAllParticipantDKGRegistrations(_ context.Context, _ string, _ uint32) ([]*pb.DKGRegistration, error) {
	return nil, nil
}

func (m *concurrencyTestQueryClient) GetLatestActiveDKGNetwork(_ context.Context) (*pb.DKGNetwork, error) {
	return m.network, nil
}

func (m *concurrencyTestQueryClient) HasDecryptRequest(_ context.Context, _ uint32, _ string, _ string, _ string) (bool, error) {
	return true, nil
}

func (m *concurrencyTestQueryClient) VerifyStartBlock(_ context.Context, _ int64, _ []byte) error {
	return nil
}

func (m *concurrencyTestQueryClient) Close() error { return nil }

// partialDecryptServerSetup holds everything needed to call PartialDecryptTDH2.
type partialDecryptServerSetup struct {
	server *DKGServer
	req    *pb.PartialDecryptTDH2Request
}

// newPartialDecryptServerSetup builds a fully-wired DKGServer with real TDH2
// key material, pre-populated caches, and the SGX code-commitment check
// bypassed so that every call reaches the full crypto path.
func newPartialDecryptServerSetup(t *testing.T) *partialDecryptServerSetup {
	t.Helper()

	const (
		n         = 5
		threshold = 3
		round     = uint32(1)
		ourPID    = uint32(1) // this validator is party-1
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()

	// ── Shamir secret sharing ────────────────────────────────────────────────
	// Master secret x and random polynomial coefficients.
	x := suite.Scalar().Pick(suite.RandomStream())
	coeffs := make([]kyber.Scalar, threshold)
	coeffs[0] = x
	for i := 1; i < threshold; i++ {
		coeffs[i] = suite.Scalar().Pick(suite.RandomStream())
	}

	// evalAt evaluates the polynomial at a 1-based PID.
	evalAt := func(pid int) kyber.Scalar {
		z := suite.Scalar().SetInt64(int64(pid))
		acc := suite.Scalar().Zero()
		zPow := suite.Scalar().One()
		for _, c := range coeffs {
			acc.Add(acc, suite.Scalar().Mul(c, zPow))
			zPow.Set(suite.Scalar().Mul(zPow, z))
		}
		return acc
	}

	// Global public key: G*x, serialised by cb-mpc then stripped of the
	// 2-byte {SEC1-prefix, CurveID} header that buildTDH2PublicKey re-adds.
	globalPubFull, err := marshalPubShare(x)
	require.NoError(t, err)
	globalPubKey := globalPubFull[2:] // raw 32-byte Edwards25519 point

	// Party-1's private share evaluated at polynomial point 1.
	shareScalar := evalAt(int(ourPID))
	distKeyShare := &dkg.DistKeyShare{
		Commits: []kyber.Point{suite.Point().Mul(x, nil)},
		Share: &share.PriShare{
			I: int(ourPID) - 1, // Kyber uses 0-based index
			V: shareScalar,
		},
	}

	// TDH2 public key needed to encrypt the test ciphertext.
	tdh2PubKey, err := buildTDH2PublicKey(globalPubKey)
	require.NoError(t, err)
	t.Cleanup(tdh2PubKey.Free)

	// Encrypt a test message to produce the ciphertext that will be in the RPC request.
	label := []byte("concurrent-partial-decrypt-test")
	ct, err := mpc.TDH2Encrypt(tdh2PubKey, []byte("tdh2 concurrent test plaintext"), label)
	require.NoError(t, err)

	// ── DKGStore (plaintext sealer, no SGX) ──────────────────────────────────
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	stateDir := filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(keyDir, 0o755))
	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	dkgStore := store.NewDKGStoreWithSealer(keyDir, stateDir, suite, concurrencyTestSealer{})

	codeCommitment := make([]byte, 32)
	copy(codeCommitment, []byte("test-code-commit-concurrent"))
	ccHex := hex.EncodeToString(codeCommitment)

	// Persist the DistKeyShare so the store fallback path works in SGX.
	require.NoError(t, dkgStore.SealAndStoreDistKeyShare(distKeyShare, ccHex, round))
	// Generate and persist the secp256k1 signing key used by signPartialDecryptResponse.
	_, _, err = dkgStore.LoadOrGenerateSecp256k1Key(ccHex, round)
	require.NoError(t, err)

	// ── Pre-populate all in-memory caches ────────────────────────────────────
	network := &pb.DKGNetwork{Total: uint32(n), Threshold: uint32(threshold)}

	roundCtxCache := store.NewRoundContextCache()
	// Threshold > 0 ensures GetOrLoadRoundContext returns immediately from cache
	// without querying the chain.
	roundCtxCache.Set(round, &store.RoundContext{
		Round:   round,
		Network: network,
	})

	pidCache := store.NewPIDCache()
	pidCache.Set(round, ourPID)

	distKeyShareCache := store.NewDistKeyShareCache()
	distKeyShareCache.Set(round, distKeyShare)

	// ── Requester (caller's ephemeral secp256k1 key pair) ────────────────────
	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPub := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	// ── Assemble the DKGServer ────────────────────────────────────────────────
	server := &DKGServer{
		Suite:              suite,
		QueryClient:        &concurrencyTestQueryClient{network: network},
		RoundCtxCache:      roundCtxCache,
		PIDCache:           pidCache,
		DistKeyShareCache:  distKeyShareCache,
		DKGStore:           dkgStore,
		InitDKGCache:       store.NewDKGCache(),
		ResharingPrevCache: store.NewResharingDKGCache(),
		ResharingNextCache: store.NewDKGCache(),
		// Bypass SGX measurement check so all goroutines reach the crypto path.
		ValidateCodeCommitment: func([]byte) error { return nil },
	}

	req := &pb.PartialDecryptTDH2Request{
		Round:           round,
		CodeCommitment:  codeCommitment,
		Ciphertext:      ct.Bytes,
		Label:           label,
		GlobalPubKey:    globalPubKey,
		RequesterPubKey: requesterPub,
	}

	return &partialDecryptServerSetup{server: server, req: req}
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestPartialDecryptTDH2Concurrent spins up 50 goroutines that all invoke
// PartialDecryptTDH2 simultaneously on the same DKGServer.
//
// It verifies:
//  1. No goroutine hangs (all return before the test timeout).
//  2. All 50 calls succeed and return valid response fields.
//  3. When run with -race, no data races are reported.
func TestPartialDecryptTDH2Concurrent(t *testing.T) {
	t.Parallel()

	const concurrency = 50
	setup := newPartialDecryptServerSetup(t)

	type callResult struct {
		resp *pb.PartialDecryptTDH2Response
		err  error
	}

	results := make([]callResult, concurrency)
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := range concurrency {
		go func(i int) {
			defer wg.Done()
			<-ready // wait for the starting gun
			resp, err := setup.server.PartialDecryptTDH2(context.Background(), setup.req)
			results[i] = callResult{resp: resp, err: err}
		}(i)
	}

	start := time.Now()
	close(ready) // release all goroutines simultaneously
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("PartialDecryptTDH2 concurrent: %d goroutines completed in %v (avg %.2f ms/op)",
		concurrency, elapsed, float64(elapsed.Milliseconds())/float64(concurrency))

	// All goroutines must succeed and return valid response fields.
	successCount := 0
	for i, r := range results {
		if !assert.NoError(t, r.err, "goroutine %d error", i) {
			t.Logf("goroutine %d error detail: %v", i, r.err)
			continue
		}
		require.NotNil(t, r.resp, "goroutine %d: nil response", i)
		assert.NotEmpty(t, r.resp.EncryptedPartialDecryption, "goroutine %d: empty encrypted partial", i)
		assert.NotEmpty(t, r.resp.EphemeralPubKey, "goroutine %d: empty ephemeral pubkey", i)
		assert.NotEmpty(t, r.resp.PubShare, "goroutine %d: empty pub share", i)
		assert.NotEmpty(t, r.resp.Signature, "goroutine %d: empty signature", i)
		successCount++
	}
	t.Logf("result: %d/%d goroutines returned success with valid response fields", successCount, concurrency)
	require.Equal(t, concurrency, successCount, "not all goroutines succeeded")
}

// latencyStats computes min/max/p50/p95 from a slice of durations.
func latencyStats(ds []time.Duration) (min, max, p50, p95 time.Duration) {
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	// insertion sort — n is small (≤100)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	min = sorted[0]
	max = sorted[len(sorted)-1]
	p50 = sorted[len(sorted)*50/100]
	p95 = sorted[len(sorted)*95/100]
	return
}

// TestPartialDecryptTDH2SerialVsConcurrent compares wall-clock time for serial
// and concurrent invocations of PartialDecryptTDH2 and prints a detailed
// latency breakdown (min/p50/p95/max and wall-clock speedup).
func TestPartialDecryptTDH2SerialVsConcurrent(t *testing.T) {
	const ops = 50
	setup := newPartialDecryptServerSetup(t)

	// ── Warm-up: one call to prime any lazy init ──────────────────────────────
	_, err := setup.server.PartialDecryptTDH2(context.Background(), setup.req)
	require.NoError(t, err, "warm-up call failed")

	// ── Serial ────────────────────────────────────────────────────────────────
	serialLatencies := make([]time.Duration, ops)
	serialStart := time.Now()
	for i := range ops {
		t0 := time.Now()
		resp, err := setup.server.PartialDecryptTDH2(context.Background(), setup.req)
		serialLatencies[i] = time.Since(t0)
		require.NoError(t, err, "serial call %d failed", i)
		require.NotNil(t, resp)
	}
	serialTotal := time.Since(serialStart)

	// ── Concurrent ────────────────────────────────────────────────────────────
	concLatencies := make([]time.Duration, ops)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(ops)
	ready := make(chan struct{})
	for i := range ops {
		go func(i int) {
			defer wg.Done()
			<-ready
			t0 := time.Now()
			resp, err := setup.server.PartialDecryptTDH2(context.Background(), setup.req)
			lat := time.Since(t0)
			mu.Lock()
			concLatencies[i] = lat
			mu.Unlock()
			assert.NoError(t, err, "concurrent call %d failed", i)
			assert.NotNil(t, resp)
		}(i)
	}
	concurrentStart := time.Now()
	close(ready)
	wg.Wait()
	concurrentTotal := time.Since(concurrentStart)

	// ── Report ────────────────────────────────────────────────────────────────
	sMin, sMax, sP50, sP95 := latencyStats(serialLatencies)
	cMin, cMax, cP50, cP95 := latencyStats(concLatencies)

	var serialTotalMs = float64(serialTotal.Microseconds()) / 1000
	var concTotalMs = float64(concurrentTotal.Microseconds()) / 1000

	t.Logf("")
	t.Logf("┌─────────────────────────────────────────────────────────────┐")
	t.Logf("│         PartialDecryptTDH2  serial vs concurrent (%d ops)  │", ops)
	t.Logf("├──────────────┬──────────────────────────────────────────────┤")
	t.Logf("│              │  wall-clock  │   min   │   p50   │   p95   │   max   │")
	t.Logf("├──────────────┼──────────────┼─────────┼─────────┼─────────┼─────────┤")
	t.Logf("│ serial       │  %8.2f ms │ %6.2fms│ %6.2fms│ %6.2fms│ %6.2fms│",
		serialTotalMs,
		float64(sMin.Microseconds())/1000,
		float64(sP50.Microseconds())/1000,
		float64(sP95.Microseconds())/1000,
		float64(sMax.Microseconds())/1000,
	)
	t.Logf("│ concurrent   │  %8.2f ms │ %6.2fms│ %6.2fms│ %6.2fms│ %6.2fms│",
		concTotalMs,
		float64(cMin.Microseconds())/1000,
		float64(cP50.Microseconds())/1000,
		float64(cP95.Microseconds())/1000,
		float64(cMax.Microseconds())/1000,
	)
	t.Logf("├──────────────┴──────────────┴─────────┴─────────┴─────────┴─────────┤")
	if concurrentTotal > 0 {
		speedup := float64(serialTotal) / float64(concurrentTotal)
		t.Logf("│  wall-clock speedup: %.2fx  (serial_total / concurrent_wall_clock)     │", speedup)
		if speedup > 1.5 {
			t.Logf("│  ✓ concurrent is faster — TDH2PartialDecrypt is parallelisable        │")
		} else {
			t.Logf("│  ✗ little or no speedup — possible serialisation inside CGO library   │")
		}
	}
	t.Logf("└─────────────────────────────────────────────────────────────┘")
}

// TestTDH2AllPartiesConcurrent runs partial decryption for all n parties in
// parallel goroutines and then combines the results to recover the original
// plaintext. This verifies end-to-end correctness when the crypto calls
// happen concurrently.
func TestTDH2AllPartiesConcurrent(t *testing.T) {
	t.Parallel()

	const (
		n         = 5
		threshold = 3
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, as, privShares, pubShares, pids := shamirSetup(t, suite, n, threshold)

	plaintext := []byte("all parties concurrent test")
	label := []byte("all-parties-concurrent-label")

	ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
	require.NoError(t, err)

	// All n parties perform their partial decryption concurrently.
	type partyResult struct {
		name string
		pd   *mpc.TDH2PartialDecryption
		err  error
	}

	results := make([]partyResult, n)
	parties := make([]string, 0, n)
	for name := range privShares {
		parties = append(parties, name)
	}

	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)

	for i, name := range parties {
		go func(i int, name string) {
			defer wg.Done()
			<-ready
			pd, err := mpc.TDH2PartialDecrypt(pids[name], privShares[name], pubKey, ct, label)
			results[i] = partyResult{name: name, pd: pd, err: err}
		}(i, name)
	}

	start := time.Now()
	close(ready)
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("all %d parties concurrent partial decrypt: %v (avg %.2f ms/party)",
		n, elapsed, float64(elapsed.Milliseconds())/float64(n))

	// Every party must succeed.
	partials := make(map[string]*mpc.TDH2PartialDecryption, n)
	for _, r := range results {
		require.NoError(t, r.err, "party %s: TDH2PartialDecrypt failed", r.name)
		require.NotNil(t, r.pd)
		partials[r.name] = r.pd
	}

	// Combine and verify recovery of the original plaintext.
	recovered, err := mpc.TDH2Combine(as, pubKey, pubShares, ct, label, partials)
	require.NoError(t, err, "TDH2Combine failed after concurrent partial decryptions")
	assert.Equal(t, plaintext, recovered,
		"recovered plaintext differs from original after concurrent partial decryptions")
}

// TestTDH2SinglePartyConcurrent simulates 100 clients simultaneously requesting
// partial decryption from the same validator (party-1). It stresses the cb-mpc
// CGO library's thread safety by sharing the pubKey, privShare, and ciphertext
// objects across goroutines.
//
// Correctness is verified by picking one partial decryption from the concurrent
// results and combining it with serially-computed results from the remaining
// threshold−1 parties to recover the original plaintext.
func TestTDH2SinglePartyConcurrent(t *testing.T) {
	t.Parallel()

	const (
		n          = 5
		threshold  = 3
		numClients = 100 // concurrent clients requesting from party-1
	)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	pubKey, as, privShares, pubShares, pids := shamirSetup(t, suite, n, threshold)

	plaintext := []byte("single party concurrent test")
	label := []byte("single-party-concurrent-label")

	ct, err := mpc.TDH2Encrypt(pubKey, plaintext, label)
	require.NoError(t, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(t, err)
	requesterPub := ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	party1Priv := privShares["party-1"]
	party1PID := pids["party-1"]

	type clientResult struct {
		pdBytes  []byte
		encBytes []byte
		err      error
	}
	clientResults := make([]clientResult, numClients)

	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClients)

	for i := range numClients {
		go func(i int) {
			defer wg.Done()
			<-ready

			pd, err := mpc.TDH2PartialDecrypt(party1PID, party1Priv, pubKey, ct, label)
			if err != nil {
				clientResults[i] = clientResult{err: err}
				return
			}
			enc, _, err := encryptPartialToRequester(requesterPub, pd.Bytes)
			clientResults[i] = clientResult{pdBytes: pd.Bytes, encBytes: enc, err: err}
		}(i)
	}

	start := time.Now()
	close(ready)
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("party-1 concurrent: %d clients in %v (avg %.2f ms/op)",
		numClients, elapsed, float64(elapsed.Milliseconds())/float64(numClients))

	// All clients must succeed.
	successCount := 0
	for i, r := range clientResults {
		require.NoError(t, r.err, "client %d error", i)
		assert.NotEmpty(t, r.pdBytes, "client %d: empty partial decryption", i)
		assert.NotEmpty(t, r.encBytes, "client %d: empty encrypted partial", i)
		successCount++
	}
	t.Logf("%d/%d client requests succeeded", successCount, numClients)

	// Verify correctness: combine party-1's concurrent result with
	// serially-computed results from parties 2 and 3 to recover the plaintext.
	pd2, err := mpc.TDH2PartialDecrypt(pids["party-2"], privShares["party-2"], pubKey, ct, label)
	require.NoError(t, err)
	pd3, err := mpc.TDH2PartialDecrypt(pids["party-3"], privShares["party-3"], pubKey, ct, label)
	require.NoError(t, err)

	combinePartials := map[string]*mpc.TDH2PartialDecryption{
		"party-1": {Bytes: clientResults[0].pdBytes},
		"party-2": pd2,
		"party-3": pd3,
	}
	recovered, err := mpc.TDH2Combine(as, pubKey, pubShares, ct, label, combinePartials)
	require.NoError(t, err, "TDH2Combine failed using party-1 result from concurrent execution")
	assert.Equal(t, plaintext, recovered,
		"concurrent party-1 partial decryption produced incorrect result")
}

// ─── benchmarks ──────────────────────────────────────────────────────────────

// benchmarkTDH2Setup creates the objects needed for the TDH2 benchmarks.
// It uses a 3-of-5 Shamir setup and returns shared objects that are safe to
// read concurrently (pubKey, privShare, ciphertext).
func benchmarkTDH2Setup(b *testing.B) (
	pubKey *mpc.TDH2PublicKey,
	privShare *mpc.TDH2PrivateShare,
	ct *mpc.TDH2Ciphertext,
	label []byte,
	requesterPub []byte,
) {
	b.Helper()

	const threshold = 3

	suite := edwards25519.NewBlakeSHA256Ed25519()

	x := suite.Scalar().Pick(suite.RandomStream())
	coeffs := make([]kyber.Scalar, threshold)
	coeffs[0] = x
	for i := 1; i < threshold; i++ {
		coeffs[i] = suite.Scalar().Pick(suite.RandomStream())
	}

	evalAt := func(pid int) kyber.Scalar {
		z := suite.Scalar().SetInt64(int64(pid))
		acc := suite.Scalar().Zero()
		zPow := suite.Scalar().One()
		for _, c := range coeffs {
			acc.Add(acc, suite.Scalar().Mul(c, zPow))
			zPow.Set(suite.Scalar().Mul(zPow, z))
		}
		return acc
	}

	globalPubFull, err := marshalPubShare(x)
	require.NoError(b, err)

	pubKey, err = buildTDH2PublicKey(globalPubFull[2:])
	require.NoError(b, err)
	b.Cleanup(pubKey.Free)

	privShare, err = bytes2PrivateShare(evalAt(1))
	require.NoError(b, err)

	label = []byte("bench-label")
	ct, err = mpc.TDH2Encrypt(pubKey, []byte("benchmark plaintext"), label)
	require.NoError(b, err)

	requesterPriv, err := ecdsa.GenerateKey(ecrypto.S256(), rand.Reader)
	require.NoError(b, err)
	requesterPub = ecrypto.FromECDSAPub(&requesterPriv.PublicKey)

	return pubKey, privShare, ct, label, requesterPub
}

// BenchmarkTDH2PartialDecryptSerial measures single-goroutine throughput of
// one TDH2PartialDecrypt + encryptPartialToRequester cycle — the core of a
// single PartialDecryptTDH2 call.
func BenchmarkTDH2PartialDecryptSerial(b *testing.B) {
	pubKey, privShare, ct, label, requesterPub := benchmarkTDH2Setup(b)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		pd, err := mpc.TDH2PartialDecrypt(1, privShare, pubKey, ct, label)
		if err != nil {
			b.Fatalf("TDH2PartialDecrypt: %v", err)
		}
		if _, _, err := encryptPartialToRequester(requesterPub, pd.Bytes); err != nil {
			b.Fatalf("encryptPartialToRequester: %v", err)
		}
	}
}

// BenchmarkTDH2PartialDecryptParallel measures concurrent throughput of the
// same cycle with GOMAXPROCS goroutines, each sharing the same pubKey,
// privShare, and ciphertext objects. A significant throughput drop compared
// to the serial benchmark indicates serialization inside the CGO library.
func BenchmarkTDH2PartialDecryptParallel(b *testing.B) {
	pubKey, privShare, ct, label, requesterPub := benchmarkTDH2Setup(b)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pd, err := mpc.TDH2PartialDecrypt(1, privShare, pubKey, ct, label)
			if err != nil {
				b.Errorf("TDH2PartialDecrypt: %v", err)
				return
			}
			if _, _, err := encryptPartialToRequester(requesterPub, pd.Bytes); err != nil {
				b.Errorf("encryptPartialToRequester: %v", err)
				return
			}
		}
	})
}
