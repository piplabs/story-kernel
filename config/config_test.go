package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGRPCConfig_Validate tests all validation rules for GRPCConfig (TLS/mTLS).
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

// TestConfig_Validate tests the internal Config.validate method.
func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("empty listen addr fails", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			GRPC:        GRPCConfig{ListenAddr: ""},
			LightClient: validLightClientConfig(),
		}
		err := cfg.validate()
		require.ErrorContains(t, err, "listen address for gRPC should not be empty")
	})

	t.Run("invalid light client config fails", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			GRPC:        GRPCConfig{ListenAddr: ":50051"},
			LightClient: LightClientConfig{ChainID: ""}, // intentionally empty
		}
		err := cfg.validate()
		require.ErrorContains(t, err, "validate light client config")
	})

	t.Run("valid config passes", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			GRPC:        GRPCConfig{ListenAddr: ":50051"},
			LightClient: validLightClientConfig(),
		}
		err := cfg.validate()
		require.NoError(t, err)
	})
}

// TestConfig_HomeDir tests home directory accessors.
func TestConfig_HomeDir(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	cfg.SetHomeDir("/home/test")
	require.Equal(t, "/home/test", cfg.GetHomeDir())
	require.Equal(t, "/home/test/"+KeysDir, cfg.GetKeysDir())
	require.Equal(t, "/home/test/"+DKGStateDir, cfg.GetDKGStateDir())
	require.Equal(t, "/home/test/"+LightClientDir, cfg.GetLightClientDir())
}

// TestConfig_HomeDirEmpty tests that empty home directory produces expected paths.
func TestConfig_HomeDirEmpty(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	require.Equal(t, "", cfg.GetHomeDir())
	require.Equal(t, KeysDir, cfg.GetKeysDir())
	require.Equal(t, DKGStateDir, cfg.GetDKGStateDir())
	require.Equal(t, LightClientDir, cfg.GetLightClientDir())
}

// TestLightClientConfig_Validate tests all validation rules for LightClientConfig.
func TestLightClientConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     LightClientConfig
		wantErr string
	}{
		{
			name:    "empty chain ID is rejected",
			cfg:     LightClientConfig{},
			wantErr: "chain id should not be empty",
		},
		{
			name:    "empty RPC addr is rejected",
			cfg:     LightClientConfig{ChainID: "story"},
			wantErr: "RPC address should not be empty",
		},
		{
			name:    "empty primary addr is rejected",
			cfg:     LightClientConfig{ChainID: "story", RPCAddr: "http://localhost:26657"},
			wantErr: "primary address should not be empty",
		},
		{
			name: "zero witnesses is rejected",
			cfg: LightClientConfig{
				ChainID:      "story",
				RPCAddr:      "http://localhost:26657",
				PrimaryAddr:  "http://localhost:26657",
				WitnessAddrs: []string{},
			},
			wantErr: "at least 2 witness addresses are required",
		},
		{
			name: "one witness is rejected",
			cfg: LightClientConfig{
				ChainID:      "story",
				RPCAddr:      "http://localhost:26657",
				PrimaryAddr:  "http://localhost:26657",
				WitnessAddrs: []string{"http://w1:26657"},
			},
			wantErr: "at least 2 witness addresses are required",
		},
		{
			name: "zero trusted height is rejected",
			cfg: LightClientConfig{
				ChainID:       "story",
				RPCAddr:       "http://localhost:26657",
				PrimaryAddr:   "http://localhost:26657",
				WitnessAddrs:  []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight: 0,
			},
			wantErr: "trusted height should not be zero",
		},
		{
			name: "empty trusted hash is rejected",
			cfg: LightClientConfig{
				ChainID:       "story",
				RPCAddr:       "http://localhost:26657",
				PrimaryAddr:   "http://localhost:26657",
				WitnessAddrs:  []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight: 100,
				TrustedHash:   "",
			},
			wantErr: "trusted hash should not be empty",
		},
		{
			name: "negative trusted period is rejected",
			cfg: LightClientConfig{
				ChainID:       "story",
				RPCAddr:       "http://localhost:26657",
				PrimaryAddr:   "http://localhost:26657",
				WitnessAddrs:  []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight: 100,
				TrustedHash:   "abc123",
				TrustedPeriod: -1,
			},
			wantErr: "trusted period must not be negative",
		},
		{
			name: "negative max block wait retries is rejected",
			cfg: LightClientConfig{
				ChainID:             "story",
				RPCAddr:             "http://localhost:26657",
				PrimaryAddr:         "http://localhost:26657",
				WitnessAddrs:        []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight:       100,
				TrustedHash:         "abc123",
				MaxBlockWaitRetries: -1,
			},
			wantErr: "max block wait retries must not be negative",
		},
		{
			name: "negative block wait retry delay is rejected",
			cfg: LightClientConfig{
				ChainID:             "story",
				RPCAddr:             "http://localhost:26657",
				PrimaryAddr:         "http://localhost:26657",
				WitnessAddrs:        []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight:       100,
				TrustedHash:         "abc123",
				BlockWaitRetryDelay: -1,
			},
			wantErr: "block wait retry delay must not be negative",
		},
		{
			name:    "valid config is accepted",
			cfg:     validLightClientConfig(),
			wantErr: "",
		},
		{
			name: "config with custom positive periods is accepted",
			cfg: LightClientConfig{
				ChainID:             "story",
				RPCAddr:             "http://localhost:26657",
				PrimaryAddr:         "http://localhost:26657",
				WitnessAddrs:        []string{"http://w1:26657", "http://w2:26657"},
				TrustedHeight:       100,
				TrustedHash:         "abc123",
				TrustedPeriod:       48 * time.Hour,
				MaxBlockWaitRetries: 5,
				BlockWaitRetryDelay: 2 * time.Second,
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLightClientConfig_GetTrustedPeriod tests the GetTrustedPeriod getter.
func TestLightClientConfig_GetTrustedPeriod(t *testing.T) {
	t.Parallel()

	t.Run("zero returns default 2 weeks", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{}
		expected := 2 * 7 * 24 * time.Hour
		require.Equal(t, expected, cfg.GetTrustedPeriod())
	})

	t.Run("custom value is returned as-is", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{TrustedPeriod: 48 * time.Hour}
		require.Equal(t, 48*time.Hour, cfg.GetTrustedPeriod())
	})

	t.Run("1 hour is not overridden", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{TrustedPeriod: time.Hour}
		require.Equal(t, time.Hour, cfg.GetTrustedPeriod())
	})
}

// TestLightClientConfig_GetMaxBlockWaitRetries tests the GetMaxBlockWaitRetries getter.
func TestLightClientConfig_GetMaxBlockWaitRetries(t *testing.T) {
	t.Parallel()

	t.Run("zero returns default 10", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{}
		require.Equal(t, 10, cfg.GetMaxBlockWaitRetries())
	})

	t.Run("custom value is returned as-is", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{MaxBlockWaitRetries: 20}
		require.Equal(t, 20, cfg.GetMaxBlockWaitRetries())
	})

	t.Run("value of 1 is not overridden", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{MaxBlockWaitRetries: 1}
		require.Equal(t, 1, cfg.GetMaxBlockWaitRetries())
	})
}

// TestLightClientConfig_GetBlockWaitRetryDelay tests the GetBlockWaitRetryDelay getter.
func TestLightClientConfig_GetBlockWaitRetryDelay(t *testing.T) {
	t.Parallel()

	t.Run("zero returns default 1 second", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{}
		require.Equal(t, time.Second, cfg.GetBlockWaitRetryDelay())
	})

	t.Run("custom value is returned as-is", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{BlockWaitRetryDelay: 5 * time.Second}
		require.Equal(t, 5*time.Second, cfg.GetBlockWaitRetryDelay())
	})

	t.Run("nanosecond precision is preserved", func(t *testing.T) {
		t.Parallel()
		cfg := LightClientConfig{BlockWaitRetryDelay: 500 * time.Millisecond}
		require.Equal(t, 500*time.Millisecond, cfg.GetBlockWaitRetryDelay())
	})
}

// TestDefaultConfig tests the DefaultConfig constructor.
func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	require.Equal(t, "info", cfg.LogLevel)
	require.Equal(t, ":50051", cfg.GRPC.ListenAddr)
	require.Equal(t, "http://localhost:26657", cfg.LightClient.RPCAddr)
	require.Equal(t, "http://localhost:26657", cfg.LightClient.PrimaryAddr)
	require.Empty(t, cfg.LightClient.ChainID)
	require.Empty(t, cfg.LightClient.TrustedHash)
	require.Zero(t, cfg.LightClient.TrustedHeight)
}

// TestConstants tests package-level constants.
func TestConstants(t *testing.T) {
	t.Parallel()

	require.Equal(t, "keys", KeysDir)
	require.Equal(t, "dkg_state", DKGStateDir)
	require.Equal(t, "light_client", LightClientDir)
	require.Equal(t, "dkg.sealed", DKGFile)
	require.Equal(t, "dist_key_share.sealed", DistKeyShareFile)
	require.Equal(t, 2, MinWitnessCount)
}

// TestWriteReadConfigTOML tests the full TOML write→read round-trip.
func TestWriteReadConfigTOML(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")

	original := DefaultConfig()
	original.SetHomeDir(tmpDir)
	original.LogLevel = "debug"
	original.GRPC.ListenAddr = ":9090"
	original.LightClient.ChainID = "story-testnet"
	original.LightClient.RPCAddr = "http://rpc.example.com:26657"
	original.LightClient.PrimaryAddr = "http://primary.example.com:26657"
	original.LightClient.WitnessAddrs = []string{
		"http://w1.example.com:26657",
		"http://w2.example.com:26657",
	}
	original.LightClient.TrustedHeight = 12345
	original.LightClient.TrustedHash = "abc123def456"

	require.NoError(t, WriteConfigTOML(cfgPath, original))

	loaded, err := ReadConfigTOML(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "debug", loaded.LogLevel)
	require.Equal(t, ":9090", loaded.GRPC.ListenAddr)
	require.Equal(t, "story-testnet", loaded.LightClient.ChainID)
	require.Equal(t, "http://rpc.example.com:26657", loaded.LightClient.RPCAddr)
	require.Equal(t, "http://primary.example.com:26657", loaded.LightClient.PrimaryAddr)
	require.Len(t, loaded.LightClient.WitnessAddrs, 2)
	require.Equal(t, int64(12345), loaded.LightClient.TrustedHeight)
	require.Equal(t, "abc123def456", loaded.LightClient.TrustedHash)
}

// TestReadConfigTOML_FileNotFound tests error handling when TOML file does not exist.
func TestReadConfigTOML_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := ReadConfigTOML("/nonexistent/path/config.toml")
	require.ErrorContains(t, err, "failed to read config file")
}

// TestReadConfigTOML_InvalidValidation tests that invalid config values fail validation on read.
func TestReadConfigTOML_InvalidValidation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")

	// Syntactically valid TOML but semantically invalid (empty listen_addr, empty chain_id).
	toml := `
log-level = "info"

[grpc]
listen_addr = ""

[light_client]
chain_id = ""
rpc_addr = ""
primary_addr = ""
witness_addrs = []
trusted_height = 0
trusted_hash = ""
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(toml), 0o600))

	_, err := ReadConfigTOML(cfgPath)
	require.ErrorContains(t, err, "invalid config")
}

// TestWriteConfigTOML_DirectoryCreation tests write succeeds in an existing directory.
func TestWriteConfigTOML_DirectoryCreation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")

	cfg := DefaultConfig()
	cfg.LightClient.WitnessAddrs = []string{"http://w1:26657", "http://w2:26657"}

	err := WriteConfigTOML(cfgPath, cfg)
	require.NoError(t, err)

	// File should exist
	_, statErr := os.Stat(cfgPath)
	require.NoError(t, statErr)
}

// validLightClientConfig returns a valid LightClientConfig for use in tests.
func validLightClientConfig() LightClientConfig {
	return LightClientConfig{
		ChainID:       "story",
		RPCAddr:       "http://localhost:26657",
		PrimaryAddr:   "http://localhost:26657",
		WitnessAddrs:  []string{"http://w1:26657", "http://w2:26657"},
		TrustedHeight: 100,
		TrustedHash:   "abc123",
	}
}
