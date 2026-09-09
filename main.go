package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/unicrons/powerpipe-securityhub-importer/cmd"
	"github.com/unicrons/powerpipe-securityhub-importer/importer"
)

// newImporterFunc abstracts importer.New so tests can inject a fake Importer instead of hitting
// real AWS. Production code always passes importer.New itself.
type newImporterFunc func(ctx context.Context, opts importer.Options) (importer.Importer, error)

func run(ctx context.Context, log *slog.Logger, flags *cmd.Flags, newImporter newImporterFunc) error {
	findings, err := readFindingsFile(flags.FindingsFile)
	if err != nil {
		return err
	}
	log.Info("read findings file", "path", flags.FindingsFile, "count", len(findings))

	imp, err := newImporter(ctx, importer.Options{
		RoleName:    flags.RoleName,
		SessionName: flags.SessionName,
		OnlyFailed:  flags.OnlyFailed,
	})
	if err != nil {
		return fmt.Errorf("creating importer: %w", err)
	}

	result, err := imp.Import(ctx, findings)
	log.Info("securityhub finding import finished", "imported", result.Imported, "failed", result.Failed)
	if err != nil {
		return fmt.Errorf("importing findings: %w", err)
	}
	return nil
}

func readFindingsFile(path string) ([]types.AwsSecurityFinding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading findings file: %w", err)
	}

	var findings []types.AwsSecurityFinding
	if err := json.Unmarshal(content, &findings); err != nil {
		return nil, fmt.Errorf("parsing findings file: %w", err)
	}
	return findings, nil
}

func main() {
	root := cmd.NewRootCmd(func(ctx context.Context, log *slog.Logger, flags *cmd.Flags) error {
		return run(ctx, log, flags, importer.New)
	})
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
