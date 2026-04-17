package buildinfo

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	VersionMajor = 0          // Major version component of the current release
	VersionMinor = 1          // Minor version component of the current release
	VersionPatch = 1          // Patch version component of the current release
	VersionMeta  = "unstable" // Version metadata to append to the version string
)

// GitCommit and GitTimestamp are set via -ldflags at build time.
// The SGX reproducible build uses -buildvcs=false, so runtime/debug
// build settings are unavailable. These variables are the fallback.
var (
	GitCommit    = "unknown"
	GitTimestamp = "unknown"
)

// Version returns the semantic version string.
func Version() string {
	return fmt.Sprintf("v%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
}

// VersionWithMeta returns the version string including metadata.
func VersionWithMeta() string {
	v := Version()
	if VersionMeta != "" {
		v += "-" + VersionMeta
	}

	return v
}

// NewVersionCmd returns a cobra command that prints build info.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version information of this binary",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			var sb strings.Builder

			_, _ = sb.WriteString("Version       " + VersionWithMeta())
			_, _ = sb.WriteString("\n")
			_, _ = sb.WriteString("Git Commit    " + GitCommit)
			_, _ = sb.WriteString("\n")
			_, _ = sb.WriteString("Git Timestamp " + GitTimestamp)
			_, _ = sb.WriteString("\n")

			cmd.Print(sb.String())
		},
	}
}
