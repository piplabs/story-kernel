package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/piplabs/story-kernel/config"
)

const (
	configFileName = "config.toml"
)

var rootCmd = &cobra.Command{
	Use:   "story-kernel",
	Short: "A daemon of TEE client for IP Vault",
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	defaultAppHomeDir := filepath.Join(userHomeDir, ".story-kernel")

	rootCmd.PersistentFlags().String(FlagHome, defaultAppHomeDir, "home directory")

	rootCmd.AddCommand(
		initCmd,
		startCmd,
	)
}

func loadConfigFromHome(cmd *cobra.Command) (*config.Config, error) {
	homeDir, err := cmd.Flags().GetString(FlagHome)
	if err != nil {
		return nil, fmt.Errorf("failed to read a home flag: %w", err)
	}

	conf, err := config.ReadConfigTOML(getConfigPath(homeDir))
	if err != nil {
		return nil, fmt.Errorf("failed to read config from file: %w", err)
	}
	conf.SetHomeDir(homeDir)

	if err := initLogger(conf); err != nil {
		return nil, fmt.Errorf("failed to init logger: %w", err)
	}

	return conf, nil
}

func getConfigPath(homeDir string) string {
	return filepath.Join(homeDir, configFileName)
}

func initLogger(conf *config.Config) error {
	logLevel, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to parse log level: %w", err)
	}

	log.SetLevel(logLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})

	return nil
}
