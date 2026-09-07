package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/unicrons/powerpipe-securityhub-importer/cmd"
	"github.com/unicrons/powerpipe-securityhub-importer/importer"
)

// fakeImporter is an in-memory importer.Importer - no AWS calls happen in these tests.
type fakeImporter struct {
	result importer.Result
	err    error
}

func (f *fakeImporter) Import(ctx context.Context, findings []types.AwsSecurityFinding) (importer.Result, error) {
	return f.result, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func writeFindingsFile(t *testing.T, findings []types.AwsSecurityFinding) string {
	t.Helper()

	content, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshaling test findings: %v", err)
	}

	path := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing test findings file: %v", err)
	}
	return path
}

func TestRun(t *testing.T) {
	path := writeFindingsFile(t, []types.AwsSecurityFinding{{}})
	fake := &fakeImporter{result: importer.Result{Imported: 3}}
	newImporter := func(ctx context.Context, opts importer.Options) (importer.Importer, error) {
		return fake, nil
	}

	flags := &cmd.Flags{FindingsFile: path}

	if err := run(t.Context(), discardLogger(), flags, newImporter); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_NewImporterError(t *testing.T) {
	path := writeFindingsFile(t, nil)
	wantErr := errors.New("boom")
	newImporter := func(ctx context.Context, opts importer.Options) (importer.Importer, error) {
		return nil, wantErr
	}

	err := run(t.Context(), discardLogger(), &cmd.Flags{FindingsFile: path}, newImporter)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

// TestRun_ImportError_StillLogsResult ensures a partial import failure doesn't hide what
// succeeded: the aggregate Result must be logged even when Import also returns an error, since
// the importer's best-effort design (see the importer package) is only useful if the operator
// can see what succeeded alongside what failed.
func TestRun_ImportError_StillLogsResult(t *testing.T) {
	path := writeFindingsFile(t, nil)
	wantErr := errors.New("boom")
	fake := &fakeImporter{result: importer.Result{Imported: 7, Failed: 2}, err: wantErr}
	newImporter := func(ctx context.Context, opts importer.Options) (importer.Importer, error) {
		return fake, nil
	}

	log, buf := bufferLogger()
	err := run(t.Context(), log, &cmd.Flags{FindingsFile: path}, newImporter)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}

	out := buf.String()
	for _, want := range []string{"imported=7", "failed=2"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output = %q, want it to contain %q", out, want)
		}
	}
}

func TestRun_ReadFindingsFileError(t *testing.T) {
	newImporter := func(ctx context.Context, opts importer.Options) (importer.Importer, error) {
		t.Fatal("newImporter should not be called when the findings file can't be read")
		return nil, nil
	}

	err := run(t.Context(), discardLogger(), &cmd.Flags{FindingsFile: "/no/such/file.json"}, newImporter)
	if err == nil {
		t.Fatal("expected an error for a missing findings file")
	}
}

func TestReadFindingsFile(t *testing.T) {
	id1, id2 := "id-1", "id-2"
	path := writeFindingsFile(t, []types.AwsSecurityFinding{{Id: &id1}, {Id: &id2}})

	got, err := readFindingsFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
}

func TestReadFindingsFile_NotFound(t *testing.T) {
	if _, err := readFindingsFile("/no/such/file.json"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestReadFindingsFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	if _, err := readFindingsFile(path); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}
