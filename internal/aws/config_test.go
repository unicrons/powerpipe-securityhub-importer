package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// fakeSTSAPI is an in-memory stscreds.AssumeRoleAPIClient - no AWS calls happen in these tests.
type fakeSTSAPI struct {
	output *sts.AssumeRoleOutput
	err    error

	gotParams *sts.AssumeRoleInput // params from the most recent call, for assertions
}

func (f *fakeSTSAPI) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.gotParams = params
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

func strPtr(s string) *string        { return &s }
func timePtr(t time.Time) *time.Time { return &t }

func fakeAssumeRoleOutput() *sts.AssumeRoleOutput {
	return &sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     strPtr("AKIAFAKE"),
			SecretAccessKey: strPtr("secret"),
			SessionToken:    strPtr("token"),
			Expiration:      timePtr(time.Now().Add(time.Hour)),
		},
	}
}

func TestAssumeRole(t *testing.T) {
	api := &fakeSTSAPI{output: fakeAssumeRoleOutput()}

	creds, err := assumeRole(t.Context(), api, "arn:aws:iam::111111111111:role/my-role", "test-session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.AccessKeyID != "AKIAFAKE" {
		t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, "AKIAFAKE")
	}
	if creds.SessionToken != "token" {
		t.Errorf("SessionToken = %q, want %q", creds.SessionToken, "token")
	}
}

func TestAssumeRole_Error(t *testing.T) {
	wantErr := errors.New("AccessDenied")
	api := &fakeSTSAPI{err: wantErr}

	_, err := assumeRole(t.Context(), api, "arn:aws:iam::111111111111:role/my-role", "test-session")
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestAssumeRoleConfig(t *testing.T) {
	api := &fakeSTSAPI{output: fakeAssumeRoleOutput()}

	cfg, err := AssumeRoleConfig(t.Context(), api, "arn:aws:iam::111111111111:role/my-role", "test-session", "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("Region = %q, want %q", cfg.Region, "us-east-1")
	}

	creds, err := cfg.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("retrieving credentials from resulting config: %v", err)
	}
	if creds.AccessKeyID != "AKIAFAKE" {
		t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, "AKIAFAKE")
	}
}

func TestAssumeRoleConfig_AssumeRoleError(t *testing.T) {
	wantErr := errors.New("AccessDenied")
	api := &fakeSTSAPI{err: wantErr}

	_, err := AssumeRoleConfig(t.Context(), api, "arn:aws:iam::111111111111:role/my-role", "test-session", "us-east-1")
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	// LoadDefaultConfig only resolves the local SDK config chain - it makes no network calls,
	// so this succeeds even without real AWS credentials in the environment.
	if _, err := LoadDefaultConfig(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
