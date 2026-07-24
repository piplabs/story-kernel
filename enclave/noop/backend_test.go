package noop_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/piplabs/story-kernel/enclave"
	_ "github.com/piplabs/story-kernel/enclave/noop"
)

func TestNoopFailClosed(t *testing.T) {
	b := enclave.Default()
	require.Equal(t, "noop", b.Backend())

	_, err := b.GetRemoteQuote([]byte{1})
	require.True(t, errors.Is(err, enclave.ErrNoTEE), "GetRemoteQuote: want ErrNoTEE, got %v", err)

	_, err = b.GetSelfCodeCommitment()
	require.True(t, errors.Is(err, enclave.ErrNoTEE), "GetSelfCodeCommitment: want ErrNoTEE, got %v", err)

	require.True(t, errors.Is(b.ValidateCodeCommitment([]byte{0}), enclave.ErrNoTEE),
		"ValidateCodeCommitment: want ErrNoTEE")

	_, err = b.Seal([]byte{0})
	require.True(t, errors.Is(err, enclave.ErrNoTEE), "Seal: want ErrNoTEE, got %v", err)

	_, err = b.Unseal([]byte{0})
	require.True(t, errors.Is(err, enclave.ErrNoTEE), "Unseal: want ErrNoTEE, got %v", err)

	_, err = b.NewSealedDB("x", t.TempDir())
	require.True(t, errors.Is(err, enclave.ErrNoTEE), "NewSealedDB: want ErrNoTEE, got %v", err)
}

func TestNoopBackendInterfaces(t *testing.T) {
	// Compile-time check that noop satisfies all interfaces is via the import
	// + Default() call above. This test verifies via runtime type assertion
	// that the registered backend implements every narrow interface.
	b := enclave.Default()
	require.Implements(t, (*enclave.Sealer)(nil), b)
	require.Implements(t, (*enclave.Quoter)(nil), b)
	require.Implements(t, (*enclave.Identifier)(nil), b)
}
