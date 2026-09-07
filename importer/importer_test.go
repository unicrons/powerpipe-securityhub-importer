package importer

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// fakeSecurityHubBackend is an in-memory SecurityHubBackend - no AWS calls happen in these
// tests. Results are keyed by "accountID/region"; a key with no configured result succeeds with
// zero imported/failed. It also tracks concurrent calls, for the concurrency-limit test.
type fakeSecurityHubBackend struct {
	results map[string]fakeResult

	mu    sync.Mutex
	calls []fakeCall

	current atomic.Int32
	max     atomic.Int32
}

type fakeResult struct {
	imported, failed int
	err              error
}

type fakeCall struct {
	accountID string
	region    string
	findings  []types.AwsSecurityFinding
}

func (f *fakeSecurityHubBackend) Import(ctx context.Context, accountID, region string, findings []types.AwsSecurityFinding) (int, int, error) {
	c := f.current.Add(1)
	defer f.current.Add(-1)
	for {
		m := f.max.Load()
		if c <= m || f.max.CompareAndSwap(m, c) {
			break
		}
	}

	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{accountID, region, findings})
	f.mu.Unlock()

	r := f.results[accountID+"/"+region]
	return r.imported, r.failed, r.err
}

func TestNew(t *testing.T) {
	// LoadDefaultConfig only resolves the local SDK config chain - it makes no network calls,
	// so this succeeds even without real AWS credentials in the environment.
	imp, err := New(t.Context(), Options{RoleName: "my-role"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imp == nil {
		t.Fatal("New returned a nil Importer")
	}
}

func TestImporter_Import_Basic(t *testing.T) {
	backend := &fakeSecurityHubBackend{
		results: map[string]fakeResult{
			"111111111111/us-east-1": {imported: 2},
		},
	}
	im := &importer{backend: backend, opts: Options{RoleName: "my-role"}}

	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
		findingWith("id-2", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-2"),
	}

	result, err := im.Import(t.Context(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Imported != 2 || result.Failed != 0 {
		t.Errorf("result = %+v, want {Imported: 2, Failed: 0}", result)
	}
	if len(backend.calls) != 1 {
		t.Fatalf("backend was called %d times, want 1", len(backend.calls))
	}
	if len(backend.calls[0].findings) != 2 {
		t.Errorf("backend received %d findings, want 2 (both same account/region)", len(backend.calls[0].findings))
	}
}

func TestImporter_Import_OnlyFailedFiltersFindings(t *testing.T) {
	backend := &fakeSecurityHubBackend{}
	im := &importer{backend: backend, opts: Options{RoleName: "my-role", OnlyFailed: true}}

	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "PASSED", "res-1"),
		findingWith("id-2", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-2"),
	}

	if _, err := im.Import(t.Context(), findings); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(backend.calls) != 1 || len(backend.calls[0].findings) != 1 {
		t.Fatalf("backend calls = %+v, want a single call with 1 finding (PASSED dropped)", backend.calls)
	}
	if *backend.calls[0].findings[0].Id != "id-2"+"-"+hashSHA512("res-2") {
		t.Errorf("surviving finding Id = %q, want the one derived from id-2", *backend.calls[0].findings[0].Id)
	}
}

func TestImporter_Import_AggregatesAcrossAccountsAndRegions(t *testing.T) {
	backend := &fakeSecurityHubBackend{
		results: map[string]fakeResult{
			"111111111111/us-east-1": {imported: 3},
			"111111111111/eu-west-1": {imported: 1, failed: 1},
			"222222222222/us-east-1": {imported: 5},
		},
	}
	im := &importer{backend: backend, opts: Options{RoleName: "my-role"}}

	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
		findingWith("id-2", "111111111111", "arn:aws:securityhub:eu-west-1::product/test/test", "FAILED", "res-2"),
		findingWith("id-3", "222222222222", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-3"),
	}

	result, err := im.Import(t.Context(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Imported != 9 || result.Failed != 1 {
		t.Errorf("result = %+v, want {Imported: 9, Failed: 1}", result)
	}
	if len(backend.calls) != 3 {
		t.Errorf("backend was called %d times, want 3 (one per account/region)", len(backend.calls))
	}
}

// TestImporter_Import_OneFailureIsNotSilencedOrFatal is the regression test for the bug this
// design fixes: previously, a failing account/region was logged and dropped, leaving the overall
// import to report success (exit 0) regardless. Here, one job failing must neither stop the
// others nor be lost from the returned error.
func TestImporter_Import_OneFailureIsNotSilencedOrFatal(t *testing.T) {
	wantErr := errors.New("AccessDenied")
	backend := &fakeSecurityHubBackend{
		results: map[string]fakeResult{
			"111111111111/us-east-1": {imported: 2},
			"222222222222/us-east-1": {err: wantErr},
		},
	}
	im := &importer{backend: backend, opts: Options{RoleName: "my-role"}}

	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
		findingWith("id-2", "222222222222", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-2"),
	}

	result, err := im.Import(t.Context(), findings)
	if result.Imported != 2 {
		t.Errorf("result.Imported = %d, want 2 (the other account's success must still count)", result.Imported)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "222222222222") || !strings.Contains(err.Error(), "us-east-1") {
		t.Errorf("error = %q, want it to mention the failing account and region", err.Error())
	}
	if len(backend.calls) != 2 {
		t.Errorf("backend was called %d times, want 2 (both jobs must still run)", len(backend.calls))
	}
}

func TestImporter_Import_RespectsConcurrencyLimit(t *testing.T) {
	const numAccounts = maxConcurrentImports * 2

	backend := &fakeSecurityHubBackend{}
	im := &importer{backend: backend, opts: Options{RoleName: "my-role"}}

	findings := make([]types.AwsSecurityFinding, numAccounts)
	for i := range findings {
		accountID := strconv.Itoa(i)
		findings[i] = findingWith("id-"+accountID, accountID, "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-"+accountID)
	}

	if _, err := im.Import(t.Context(), findings); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := backend.max.Load(); got > maxConcurrentImports {
		t.Errorf("observed %d concurrent backend calls, want <= %d", got, maxConcurrentImports)
	}
	if len(backend.calls) != numAccounts {
		t.Errorf("backend was called %d times, want %d", len(backend.calls), numAccounts)
	}
}
