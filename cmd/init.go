package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/piplabs/story-kernel/config"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configs in home dir",
	RunE: func(cmd *cobra.Command, args []string) error {
		homeDir, err := cmd.Flags().GetString(FlagHome)
		if err != nil {
			return fmt.Errorf("failed to read a home flag: %w", err)
		}

		if _, err := os.Stat(homeDir); err == nil {
			return fmt.Errorf("home dir(%v) already exists", homeDir)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to check home dir: %w", err)
		}

		if err := os.MkdirAll(homeDir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create config dir: %w", err)
		}

		defaultConfig := config.DefaultConfig()
		defaultConfig.SetHomeDir(homeDir)

		return config.WriteConfigTOML(getConfigPath(homeDir), defaultConfig)
	},
}
