# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-09-07

Starting with this release, `powerpipe-securityhub-importer` follows [Semantic
Versioning](./README.md#versioning). Everything below shipped since `v0.1.1`.

### Breaking changes

- CLI flags now use a double dash (`--role`) instead of a single dash (`-role`). Update any
  scripts that invoke this tool.
- The `-failed` flag has been renamed to `--only-failed` for clarity.
- The Go library API (`pkg/aws`, `pkg/logger`, `pkg/utils`) has been removed and replaced by a
  new public package, `importer`, with a different shape: an `Importer` interface, a
  `New(ctx, opts)` constructor, and an `Import(ctx, findings)` method. Anything importing the old
  `pkg/` packages directly will need to migrate.

### Added

- `--version` flag and `version` subcommand, with version/commit/date injected at build time.
- `--help` (via Cobra), documenting every flag.
- Logs now include the source file/line of the log call, the findings file path and count read,
  and the aggregate imported/failed counts for every run - even a partially failed one.

### Changed

- Migrated the CLI from the standard `flag` package to [Cobra](https://github.com/spf13/cobra).
- Restructured the codebase into an idiomatic library/CLI split: `importer/` (public library),
  `internal/aws/` and `internal/logger/` (implementation details), `cmd/` (Cobra wiring), with a
  minimal `main.go`.
- Replaced `logrus` with the standard library's `log/slog`.
- Replaced the hand-rolled goroutine/`WaitGroup` fan-out for importing across accounts/regions
  with `errgroup.SetLimit`-bounded concurrency.
- Upgraded to Go 1.27.1 and refreshed all dependencies.
- GoReleaser now injects version/commit/date via `ldflags`, and builds for Windows and as a
  universal macOS binary, in addition to linux/darwin.
- Added CI (tests with coverage, golangci-lint, govulncheck) and wired up the release workflow -
  `.goreleaser.yaml` existed before but nothing ever triggered it.
- Added Dependabot for GitHub Actions and Go module updates.

### Fixed

- Importing into multiple AWS accounts/regions concurrently used to share a single mutable
  `aws.Config`/`error` pair across goroutines - a data race. Each account/region now works from
  entirely local state.
- A failed import for one account/region (assuming the role, or the SecurityHub API call itself)
  used to be logged and silently dropped, leaving the tool to report success and exit `0`
  regardless of the failure. It now aggregates every failure - each identifiable by account and
  region - into the error the process exits non-zero with, while still importing everywhere else
  it can.
- Findings SecurityHub itself rejected (`BatchImportFindings`'s `FailedFindings`) used to be
  logged only; they're now counted and surfaced as part of that same error.
- An assume-role failure for an account/region used to report zero failed findings, regardless of
  how many were meant for it. It now counts them all as failed.
- Findings imported by this tool had no region in the SecurityHub console's default Region column
  or its "Resource Region" filter, even though the finding's own Region was set correctly -
  `Resources[].Region` is a separate field, which is now backfilled from the finding's region.

## [0.1.1] and earlier

See the [GitHub releases](https://github.com/unicrons/powerpipe-securityhub-importer/releases)
for this and earlier versions.

[Unreleased]: https://github.com/unicrons/powerpipe-securityhub-importer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/unicrons/powerpipe-securityhub-importer/compare/v0.1.1...v1.0.0
