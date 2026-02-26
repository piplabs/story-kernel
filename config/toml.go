package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const DefaultConfigTemplate = `# Story DKG TEE Configuration

# Log level (debug, info, warn, error)
log-level = "{{ .LogLevel }}"

[grpc]
# gRPC server listen address
listen_addr = "{{ .GRPC.ListenAddr }}"

[light_client]
# Chain ID of the Story network
chain_id = "{{ .LightClient.ChainID }}"

# RPC endpoint for querying the chain
rpc_addr = "{{ .LightClient.RPCAddr }}"

# Primary light client provider
primary_addr = "{{ .LightClient.PrimaryAddr }}"

# Witness light client providers (at least 2 required for cross-validation)
witness_addrs = [{{ range $i, $addr := .LightClient.WitnessAddrs }}{{ if $i }}, {{ end }}"{{ $addr }}"{{ end }}]

# Trusted block height for light client initialization
trusted_height = {{ .LightClient.TrustedHeight }}

# Trusted block hash for light client initialization (hex-encoded)
trusted_hash = "{{ .LightClient.TrustedHash }}"

# Duration for which a validated block header is trusted (0 = default 2 weeks)
# Examples: "336h" for 2 weeks, "168h" for 1 week
# trusted_period = "0s"

# Maximum retry attempts when waiting for a new block (0 = default 10)
# max_block_wait_retries = 0

# Delay between block wait retries (0 = default 1s)
# block_wait_retry_delay = "0s"
`

var configTemplate *template.Template

func init() {
	tmpl := template.New("configTemplate")

	var err error
	if configTemplate, err = tmpl.Parse(DefaultConfigTemplate); err != nil {
		log.Panic(err)
	}
}

func ReadConfigTOML(path string) (*Config, error) {
	fileExt := filepath.Ext(path)

	v := viper.New()
	v.AddConfigPath(filepath.Dir(path))
	v.SetConfigName(strings.TrimSuffix(filepath.Base(path), fileExt))
	v.SetConfigType(fileExt[1:]) // excluding the dot

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var conf Config
	if err := v.Unmarshal(&conf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := conf.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &conf, nil
}

func WriteConfigTOML(path string, config *Config) error {
	var buffer bytes.Buffer
	if err := configTemplate.Execute(&buffer, config); err != nil {
		return fmt.Errorf("failed to populate config template: %w", err)
	}

	return os.WriteFile(path, buffer.Bytes(), 0600)
}
