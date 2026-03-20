package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGRPCConfig_Validate(t *testing.T) {
	// Create temp cert files for os.Stat checks
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.crt")
	keyFile := filepath.Join(tmpDir, "server.key")
	caFile := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certFile, []byte("cert"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key"), 0o600))
	require.NoError(t, os.WriteFile(caFile, []byte("ca"), 0o600))

	tests := []struct {
		name    string
		cfg     GRPCConfig
		wantErr string
	}{
		{
			name: "no TLS (valid)",
			cfg:  GRPCConfig{ListenAddr: ":50051"},
		},
		{
			name: "TLS with cert and key (valid)",
			cfg:  GRPCConfig{ListenAddr: ":50051", TLSCertFile: certFile, TLSKeyFile: keyFile},
		},
		{
			name: "mTLS with all three (valid)",
			cfg:  GRPCConfig{ListenAddr: ":50051", TLSCertFile: certFile, TLSKeyFile: keyFile, TLSCAFile: caFile},
		},
		{
			name:    "cert without key",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSCertFile: certFile},
			wantErr: "tls_cert_file and tls_key_file must both be set or both be empty",
		},
		{
			name:    "key without cert",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSKeyFile: keyFile},
			wantErr: "tls_cert_file and tls_key_file must both be set or both be empty",
		},
		{
			name:    "CA without cert/key",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSCAFile: caFile},
			wantErr: "tls_ca_file requires tls_cert_file and tls_key_file to be set",
		},
		{
			name:    "cert file does not exist",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSCertFile: "/nonexistent/cert.pem", TLSKeyFile: keyFile},
			wantErr: "tls_cert_file",
		},
		{
			name:    "key file does not exist",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSCertFile: certFile, TLSKeyFile: "/nonexistent/key.pem"},
			wantErr: "tls_key_file",
		},
		{
			name:    "CA file does not exist",
			cfg:     GRPCConfig{ListenAddr: ":50051", TLSCertFile: certFile, TLSKeyFile: keyFile, TLSCAFile: "/nonexistent/ca.pem"},
			wantErr: "tls_ca_file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGRPCConfig_TLSEnabled(t *testing.T) {
	require.False(t, GRPCConfig{}.TLSEnabled())
	require.False(t, GRPCConfig{TLSCertFile: "cert"}.TLSEnabled())
	require.False(t, GRPCConfig{TLSKeyFile: "key"}.TLSEnabled())
	require.True(t, GRPCConfig{TLSCertFile: "cert", TLSKeyFile: "key"}.TLSEnabled())
}

func TestGRPCConfig_MTLSEnabled(t *testing.T) {
	require.False(t, GRPCConfig{}.MTLSEnabled())
	require.False(t, GRPCConfig{TLSCertFile: "cert", TLSKeyFile: "key"}.MTLSEnabled())
	require.False(t, GRPCConfig{TLSCAFile: "ca"}.MTLSEnabled())
	require.True(t, GRPCConfig{TLSCertFile: "cert", TLSKeyFile: "key", TLSCAFile: "ca"}.MTLSEnabled())
}
