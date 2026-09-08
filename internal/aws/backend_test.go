package aws

import (
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestSecurityHubBackend_Import_BuildsRoleARN(t *testing.T) {
	api := &fakeSTSAPI{output: fakeAssumeRoleOutput()}
	b := &securityHubBackend{stsClient: api, roleName: "my-role", sessionName: "test-session"}

	// No findings, so BatchImport short-circuits before any network call - this exercises the
	// whole Import path (role ARN construction, assume-role, client construction) with no real
	// AWS access required.
	imported, failed, err := b.Import(t.Context(), "111111111111", "us-east-1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imported != 0 || failed != 0 {
		t.Errorf("imported = %d, failed = %d, want 0, 0", imported, failed)
	}

	if api.gotParams == nil || api.gotParams.RoleArn == nil {
		t.Fatal("AssumeRole was not called with a RoleArn")
	}
	if want := "arn:aws:iam::111111111111:role/my-role"; *api.gotParams.RoleArn != want {
		t.Errorf("RoleArn = %q, want %q", *api.gotParams.RoleArn, want)
	}
	if api.gotParams.RoleSessionName == nil || *api.gotParams.RoleSessionName != "test-session" {
		t.Errorf("RoleSessionName = %v, want %q", api.gotParams.RoleSessionName, "test-session")
	}
}

// TestSecurityHubBackend_Import_AssumeRoleErrorCountsAllFindingsAsFailed is the regression test
// for a bug where an assume-role failure reported {imported: 0, failed: 0} regardless of how
// many findings were meant for that account/region - misleadingly suggesting nothing was lost.
func TestSecurityHubBackend_Import_AssumeRoleErrorCountsAllFindingsAsFailed(t *testing.T) {
	wantErr := errors.New("AccessDenied")
	b := &securityHubBackend{stsClient: &fakeSTSAPI{err: wantErr}, roleName: "my-role", sessionName: "test-session"}

	findings := make([]types.AwsSecurityFinding, 3)
	imported, failed, err := b.Import(t.Context(), "222222222222", "us-east-1", findings)
	if imported != 0 || failed != len(findings) {
		t.Errorf("imported = %d, failed = %d, want 0, %d", imported, failed, len(findings))
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "222222222222") {
		t.Errorf("error = %q, want it to mention the account ID", err.Error())
	}
}
