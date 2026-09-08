package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/spf13/cobra"

	"github.com/unicrons/powerpipe-securityhub-importer/internal/logger"
)

// Flags holds the parsed and validated values of the root command's flags, ready to be
// consumed by the injected run function.
type Flags struct {
	RoleName     string
	FindingsFile string
	SessionName  string
	LogFormat    string
	OnlyFailed   bool
}

var validLogFormats = []string{"default", "json"}

// NewRootCmd builds the root command. run is invoked with the request context, a logger
// configured for the requested --log format, and the fully validated flags.
func NewRootCmd(run func(ctx context.Context, log *slog.Logger, flags *Flags) error) *cobra.Command {
	var flags Flags

	cmd := &cobra.Command{
		Use:          "powerpipe-securityhub-importer",
		Short:        "Import Powerpipe AWS ASFF findings into AWS SecurityHub across accounts and regions",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains(validLogFormats, flags.LogFormat) {
				return fmt.Errorf("--log unknown value %q, valid values are: default, json", flags.LogFormat)
			}

			log := logger.New(flags.LogFormat)
			return run(cmd.Context(), log, &flags)
		},
	}

	cmd.Flags().StringVar(&flags.RoleName, "role", "", "AWS role name to assume in each account")
	cmd.Flags().StringVar(&flags.FindingsFile, "findings", "", "SecurityHub ASFF json file path")
	cmd.Flags().StringVar(&flags.SessionName, "session", "powerpipe-securityhub-importer", "AWS assume role session name")
	cmd.Flags().StringVar(&flags.LogFormat, "log", "default", "Log format: default, json")
	cmd.Flags().BoolVar(&flags.OnlyFailed, "only-failed", false, "Skip importing PASSED and NOT_AVAILABLE findings")

	for _, name := range []string{"role", "findings"} {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	cmd.Version = fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date)
	cmd.SetVersionTemplate("powerpipe-securityhub-importer {{.Version}}\n")

	cmd.AddCommand(NewVersionCmd())

	return cmd
}
