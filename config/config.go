package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

const (
	KeysDir        = "keys"
	DKGStateDir    = "dkg_state"
	LightClientDir = "light_client"

	DKGFile          = "dkg.sealed"
	DistKeyShareFile = "dist_key_share.sealed"

	// MinWitnessCount is the minimum number of witness providers required
	// for meaningful cross-validation of light client block headers.
	// A single witness cannot detect a malicious primary provider.
	MinWitnessCount = 2
)

type Config struct {
	homeDir string // not read from toml file

	LogLevel string `mapstructure:"log-level"`

	GRPC GRPCConfig `mapstructure:"grpc"`

	LightClient LightClientConfig `mapstructure:"light_client"`
}

type GRPCConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
}

type LightClientConfig struct {
	ChainID       string   `mapstructure:"chain_id"`
	RPCAddr       string   `mapstructure:"rpc_addr"`
	PrimaryAddr   string   `mapstructure:"primary_addr"`
	WitnessAddrs  []string `mapstructure:"witness_addrs"`
	TrustedHeight int64    `mapstructure:"trusted_height"`
	TrustedHash   string   `mapstructure:"trusted_hash"`

	// TrustedPeriod is the duration for which a validated block header is trusted.
	// After this period, the light client must re-verify from a new trusted block.
	// Defaults to 2 weeks if not set (0).
	TrustedPeriod time.Duration `mapstructure:"trusted_period"`

	// MaxBlockWaitRetries is the maximum number of retry attempts when waiting
	// for a new block to become available for AppHash verification.
	// Each retry waits BlockWaitRetryDelay. Defaults to 10 if not set (0).
	MaxBlockWaitRetries int `mapstructure:"max_block_wait_retries"`

	// BlockWaitRetryDelay is the delay between each block wait retry.
	// Defaults to 1s if not set (0).
	BlockWaitRetryDelay time.Duration `mapstructure:"block_wait_retry_delay"`
}

func (c *Config) validate() error {
	if c.GRPC.ListenAddr == "" {
		return errors.New("listen address for gRPC should not be empty")
	}

	if err := c.LightClient.Validate(); err != nil {
		return fmt.Errorf("validate light client config: %w", err)
	}

	return nil
}

func (c *Config) SetHomeDir(dir string) {
	c.homeDir = dir
}

func (c *Config) GetHomeDir() string {
	return c.homeDir
}

func (c *Config) GetKeysDir() string {
	return filepath.Join(c.GetHomeDir(), KeysDir)
}

func (c *Config) GetDKGStateDir() string {
	return filepath.Join(c.GetHomeDir(), DKGStateDir)
}

func (c *Config) GetLightClientDir() string {
	return filepath.Join(c.GetHomeDir(), LightClientDir)
}

func (c LightClientConfig) Validate() error {
	if c.ChainID == "" {
		return errors.New("chain id should not be empty")
	}
	if c.RPCAddr == "" {
		return errors.New("RPC address should not be empty")
	}

	if c.PrimaryAddr == "" {
		return errors.New("primary address should not be empty")
	}

	if len(c.WitnessAddrs) < MinWitnessCount {
		return fmt.Errorf("at least %d witness addresses are required for cross-validation, got %d",
			MinWitnessCount, len(c.WitnessAddrs))
	}

	if c.TrustedHeight == 0 {
		return errors.New("trusted height should not be zero")
	}

	if c.TrustedHash == "" {
		return errors.New("trusted hash should not be empty")
	}

	if c.TrustedPeriod < 0 {
		return errors.New("trusted period must not be negative")
	}

	if c.MaxBlockWaitRetries < 0 {
		return errors.New("max block wait retries must not be negative")
	}

	if c.BlockWaitRetryDelay < 0 {
		return errors.New("block wait retry delay must not be negative")
	}

	return nil
}

// GetTrustedPeriod returns the trusted period, defaulting to 2 weeks if not set.
func (c LightClientConfig) GetTrustedPeriod() time.Duration {
	if c.TrustedPeriod == 0 {
		return 2 * 7 * 24 * time.Hour // default: 2 weeks
	}

	return c.TrustedPeriod
}

// GetMaxBlockWaitRetries returns the max block wait retries, defaulting to 10 if not set.
func (c LightClientConfig) GetMaxBlockWaitRetries() int {
	if c.MaxBlockWaitRetries == 0 {
		return 10 // default: 10 retries
	}

	return c.MaxBlockWaitRetries
}

// GetBlockWaitRetryDelay returns the block wait retry delay, defaulting to 1s if not set.
func (c LightClientConfig) GetBlockWaitRetryDelay() time.Duration {
	if c.BlockWaitRetryDelay == 0 {
		return 1 * time.Second // default: 1s
	}

	return c.BlockWaitRetryDelay
}

func DefaultConfig() *Config {
	return &Config{
		LogLevel: "info",

		GRPC: GRPCConfig{
			ListenAddr: ":50051",
		},

		LightClient: LightClientConfig{
			ChainID:             "", // Must be set by user
			RPCAddr:             "http://localhost:26657",
			PrimaryAddr:         "http://localhost:26657",
			WitnessAddrs:        []string{},
			TrustedHeight:       0,  // Will be set during initialization
			TrustedHash:         "", // Will be set during initialization
			TrustedPeriod:       0,  // 0 means use default (2 weeks)
			MaxBlockWaitRetries: 0,  // 0 means use default (10)
			BlockWaitRetryDelay: 0,  // 0 means use default (1s)
		},
	}
}
