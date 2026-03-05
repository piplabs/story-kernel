package cmd

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/piplabs/story-kernel/server"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the story-kernel gRPC server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfigFromHome(cmd)
		if err != nil {
			return err
		}

		svr, errChan := server.Serve(cfg)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

		select {
		case err := <-errChan:
			if err != nil {
				log.Errorf("rpc server was closed with an error: %v", err)
			}
		case <-sigChan:
			log.Info("signal detected")
		}

		svr.GracefulStop()

		return nil
	},
}
