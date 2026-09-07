package cmd_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/unicrons/powerpipe-securityhub-importer/cmd"
)

type runFunc func(ctx context.Context, log *slog.Logger, flags *cmd.Flags) error

// execute runs cmd with the given args against a fresh command tree and returns its output and
// error. run is invoked only if flag parsing/validation succeeds.
func execute(t *testing.T, run runFunc, args ...string) (string, error) {
	t.Helper()

	root := cmd.NewRootCmd(run)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func TestNewRootCmd_HappyPath(t *testing.T) {
	var got *cmd.Flags
	run := func(_ context.Context, _ *slog.Logger, f *cmd.Flags) error {
		got = f
		return nil
	}

	_, err := execute(t, run,
		"--role", "my-role",
		"--findings", "./findings.json",
		"--session", "custom-session",
		"--log", "json",
		"--only-failed",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got == nil {
		t.Fatal("run was not called")
	}
	if got.RoleName != "my-role" {
		t.Errorf("RoleName = %q, want %q", got.RoleName, "my-role")
	}
	if got.FindingsFile != "./findings.json" {
		t.Errorf("FindingsFile = %q, want %q", got.FindingsFile, "./findings.json")
	}
	if got.SessionName != "custom-session" {
		t.Errorf("SessionName = %q, want %q", got.SessionName, "custom-session")
	}
	if got.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", got.LogFormat, "json")
	}
	if !got.OnlyFailed {
		t.Error("OnlyFailed = false, want true")
	}
}

func TestNewRootCmd_HappyPath_Defaults(t *testing.T) {
	var got *cmd.Flags
	run := func(_ context.Context, _ *slog.Logger, f *cmd.Flags) error {
		got = f
		return nil
	}

	_, err := execute(t, run, "--role", "my-role", "--findings", "./findings.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.SessionName != "powerpipe-securityhub-importer" {
		t.Errorf("SessionName default = %q, want %q", got.SessionName, "powerpipe-securityhub-importer")
	}
	if got.LogFormat != "default" {
		t.Errorf("LogFormat default = %q, want %q", got.LogFormat, "default")
	}
	if got.OnlyFailed {
		t.Error("OnlyFailed default = true, want false")
	}
}

func TestNewRootCmd_RoleRequired(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called when --role is missing")
		return nil
	}

	_, err := execute(t, run, "--findings", "./findings.json")
	if err == nil {
		t.Fatal("expected an error when --role is missing")
	}
}

func TestNewRootCmd_FindingsRequired(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called when --findings is missing")
		return nil
	}

	_, err := execute(t, run, "--role", "my-role")
	if err == nil {
		t.Fatal("expected an error when --findings is missing")
	}
}

func TestNewRootCmd_InvalidLogFormat(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called for an invalid --log value")
		return nil
	}

	_, err := execute(t, run, "--role", "my-role", "--findings", "./findings.json", "--log", "bogus")
	if err == nil {
		t.Fatal("expected an error for an invalid --log value")
	}
}

func TestNewRootCmd_RejectsPositionalArgs(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called with stray positional args")
		return nil
	}

	_, err := execute(t, run, "--role", "my-role", "--findings", "./findings.json", "unexpected-arg")
	if err == nil {
		t.Fatal("expected an error for a stray positional argument")
	}
}

func TestNewRootCmd_Version(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called for --version")
		return nil
	}

	out, err := execute(t, run, "--version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == "" {
		t.Fatal("expected non-empty output for --version")
	}
}

func TestNewVersionCmd(t *testing.T) {
	run := func(context.Context, *slog.Logger, *cmd.Flags) error {
		t.Fatal("run should not be called for the version subcommand")
		return nil
	}

	out, err := execute(t, run, "version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == "" {
		t.Fatal("expected non-empty output for the version subcommand")
	}
}
