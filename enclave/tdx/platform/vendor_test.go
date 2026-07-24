package platform

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// Registry tests
//
// These tests mutate the package-level registry, so each test snapshots and
// restores the registry around its body to avoid cross-test contamination.
// withCleanRegistry replaces the registry with an empty map for the test's
// duration and restores the original state on cleanup.
// =============================================================================

func withCleanRegistry(t *testing.T) {
	t.Helper()
	registryMu.Lock()
	prevReg := registry
	prevOrd := order
	registry = map[string]Vendor{}
	order = nil
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = prevReg
		order = prevOrd
		registryMu.Unlock()
	})
}

// fakeVendor is a minimal Vendor implementation for registry tests. It
// records the desired Probe outcome and returns a constant QuoteProvider.
type fakeVendor struct {
	name      string
	probeErr  error
	qp        QuoteProvider
	qpInitErr error
}

func (f *fakeVendor) Name() string { return f.name }
func (f *fakeVendor) Probe() error { return f.probeErr }
func (f *fakeVendor) QuoteProvider() (QuoteProvider, error) {
	if f.qpInitErr != nil {
		return nil, f.qpInitErr
	}
	return f.qp, nil
}

// fakeQuoteProvider is a trivial QuoteProvider used as a marker so tests
// can assert which vendor's provider was returned.
type fakeQuoteProvider struct{ tag string }

func (q fakeQuoteProvider) GetQuote([]byte) ([]byte, error) {
	return []byte(q.tag), nil
}

func TestRegister_DuplicateName_Panics(t *testing.T) {
	withCleanRegistry(t)
	a := &fakeVendor{name: "dup"}
	b := &fakeVendor{name: "dup"}

	Register(a)
	require.PanicsWithValue(t,
		`platform.Register: vendor "dup" already registered`,
		func() { Register(b) },
		"second Register with same name must panic",
	)
}

func TestRegister_NilVendor_Panics(t *testing.T) {
	withCleanRegistry(t)
	require.PanicsWithValue(t,
		`platform.Register: nil vendor`,
		func() { Register(nil) },
	)
}

func TestRegister_EmptyName_Panics(t *testing.T) {
	withCleanRegistry(t)
	require.PanicsWithValue(t,
		`platform.Register: vendor with empty Name()`,
		func() { Register(&fakeVendor{name: ""}) },
	)
}

func TestLookup_Hit(t *testing.T) {
	withCleanRegistry(t)
	v := &fakeVendor{name: "alpha"}
	Register(v)

	got := Lookup("alpha")
	require.Same(t, Vendor(v), got)
}

func TestLookup_Miss_ReturnsNil(t *testing.T) {
	withCleanRegistry(t)
	require.Nil(t, Lookup("missing"))
}

func TestOrder_PreservesRegistrationOrder(t *testing.T) {
	withCleanRegistry(t)
	a := &fakeVendor{name: "first"}
	b := &fakeVendor{name: "second"}
	c := &fakeVendor{name: "third"}
	Register(a)
	Register(b)
	Register(c)

	got := Order()
	require.Len(t, got, 3)
	require.Equal(t, "first", got[0].Name())
	require.Equal(t, "second", got[1].Name())
	require.Equal(t, "third", got[2].Name())
}

func TestOrder_ReturnsFreshSlice(t *testing.T) {
	withCleanRegistry(t)
	Register(&fakeVendor{name: "a"})
	Register(&fakeVendor{name: "b"})

	first := Order()
	first[0] = nil // mutate the returned slice

	second := Order()
	require.NotNil(t, second[0], "Order() must return a fresh slice; mutating one must not affect the next call")
	require.Equal(t, "a", second[0].Name())
}

func TestNames_PreservesRegistrationOrder(t *testing.T) {
	withCleanRegistry(t)
	Register(&fakeVendor{name: "x"})
	Register(&fakeVendor{name: "y"})

	require.Equal(t, []string{"x", "y"}, Names())
}

func TestNames_ReturnsFreshSlice(t *testing.T) {
	withCleanRegistry(t)
	Register(&fakeVendor{name: "x"})

	first := Names()
	first[0] = "mutated"

	second := Names()
	require.Equal(t, []string{"x"}, second)
}

func TestRegistry_ConcurrentRegister_NoRaceCorruption(t *testing.T) {
	// This test exercises the registryMu protection. Run with -race to
	// catch unsynchronized writes.
	withCleanRegistry(t)

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			Register(&fakeVendor{
				name: vendorName(i),
				qp:   fakeQuoteProvider{tag: vendorName(i)},
			})
		}(i)
	}
	wg.Wait()

	require.Len(t, Names(), n, "all concurrent Register calls must succeed")
	// Verify all names round-trip.
	for i := 0; i < n; i++ {
		require.NotNil(t, Lookup(vendorName(i)), "vendor %d must be retrievable", i)
	}
}

func vendorName(i int) string {
	const digits = "0123456789abcdef"
	return "vendor-" + string(digits[i&0x0F])
}

// =============================================================================
// Vendor interface contract — exercised via fakeVendor so tests outside this
// package have a baseline to mirror.
// =============================================================================

func TestFakeVendor_QuoteProvider_PropagatesInitError(t *testing.T) {
	sentinel := errors.New("init failed")
	v := &fakeVendor{name: "v", qpInitErr: sentinel}

	qp, err := v.QuoteProvider()
	require.Nil(t, qp)
	require.ErrorIs(t, err, sentinel)
}

// =============================================================================
// SnapshotForTesting / RestoreForTesting
//
// These are exported test hooks; their callers live in sibling packages
// (enclave/tdx/quote_test.go) and the parent's tests don't show up in this
// package's coverage report. Exercise them locally to keep the coverage
// gate satisfied per-package.
// =============================================================================

func TestSnapshotForTesting_CapturesAndRestoresState(t *testing.T) {
	withCleanRegistry(t)
	Register(&fakeVendor{name: "snap-a"})
	Register(&fakeVendor{name: "snap-b"})

	reg, ord := SnapshotForTesting()
	require.Len(t, reg, 2)
	require.Equal(t, []string{"snap-a", "snap-b"}, ord)

	// Mutate the registry: add another vendor.
	Register(&fakeVendor{name: "snap-c"})
	require.Len(t, Names(), 3)

	// Restore: registry returns to the snapshotted two-entry state.
	RestoreForTesting(reg, ord)
	require.Equal(t, []string{"snap-a", "snap-b"}, Names())
	require.Nil(t, Lookup("snap-c"))
}

func TestSnapshotForTesting_SnapshotIsIndependent(t *testing.T) {
	// The snapshot map and slice must be defensive copies so mutating
	// them does not affect the live registry, and vice versa.
	withCleanRegistry(t)
	Register(&fakeVendor{name: "indep"})

	reg, ord := SnapshotForTesting()
	require.Len(t, ord, 1, "snapshot ord captures the one registered vendor")
	delete(reg, "indep")
	ord[0] = "tampered" // in-place mutation always affects the underlying array if shared

	require.NotNil(t, Lookup("indep"), "mutating the snapshot map must not affect the live registry")
	require.Equal(t, []string{"indep"}, Names(),
		"live registry order must not be aliased to the snapshot slice")
}

func TestRestoreForTesting_FromEmpty(t *testing.T) {
	// Restoring an empty snapshot drains the registry. Used by parent-
	// package tests that want a known-empty registry baseline.
	withCleanRegistry(t)
	Register(&fakeVendor{name: "to-be-removed"})

	RestoreForTesting(map[string]Vendor{}, nil)
	require.Empty(t, Names())
	require.Nil(t, Lookup("to-be-removed"))
}

func TestRestoreForTesting_DefensiveCopy(t *testing.T) {
	// After Restore, the caller's maps/slices must not alias the live
	// registry; mutating them post-Restore must not affect Lookup.
	withCleanRegistry(t)

	v := &fakeVendor{name: "live"}
	caller := map[string]Vendor{"live": v}
	callerOrd := []string{"live"}

	RestoreForTesting(caller, callerOrd)
	delete(caller, "live")
	callerOrd[0] = "tampered"

	require.NotNil(t, Lookup("live"),
		"mutating the caller's map after Restore must not affect the live registry")
	require.Equal(t, []string{"live"}, Names())
}
