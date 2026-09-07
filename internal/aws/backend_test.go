package aws

import (
	"errors"
	"strings"
	"testing"
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

func TestSecurityHubBackend_Import_AssumeRoleErrorMentionsAccount(t *testing.T) {
	wantErr := errors.New("AccessDenied")
	b := &securityHubBackend{stsClient: &fakeSTSAPI{err: wantErr}, roleName: "my-role", sessionName: "test-session"}

	_, _, err := b.Import(t.Context(), "222222222222", "us-east-1", nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "222222222222") {
		t.Errorf("error = %q, want it to mention the account ID", err.Error())
	}
}
