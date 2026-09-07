package aws

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// fakeSecurityHubAPI is an in-memory securityHubAPI - no AWS calls happen in these tests. Each
// call returns the next entry of results/errs, indexed by call order.
type fakeSecurityHubAPI struct {
	results  []*securityhub.BatchImportFindingsOutput
	errs     []error
	calls    int
	gotSizes []int // len(params.Findings) for each call, in order
}

func (f *fakeSecurityHubAPI) BatchImportFindings(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
	i := f.calls
	f.calls++
	f.gotSizes = append(f.gotSizes, len(params.Findings))

	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return f.results[i], nil
}

func int32Ptr(i int32) *int32 { return &i }

func findingsN(n int) []types.AwsSecurityFinding {
	findings := make([]types.AwsSecurityFinding, n)
	for i := range findings {
		id := "finding-" + strconv.Itoa(i)
		findings[i] = types.AwsSecurityFinding{Id: &id}
	}
	return findings
}

func TestSecurityHubClient_BatchImport_Empty(t *testing.T) {
	api := &fakeSecurityHubAPI{}
	c := &securityHubClient{client: api}

	imported, failed, err := c.BatchImport(t.Context(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imported != 0 || failed != 0 {
		t.Errorf("imported = %d, failed = %d, want 0, 0", imported, failed)
	}
	if api.calls != 0 {
		t.Errorf("expected no API calls for an empty findings slice, got %d", api.calls)
	}
}

func TestSecurityHubClient_BatchImport_SingleChunk(t *testing.T) {
	api := &fakeSecurityHubAPI{
		results: []*securityhub.BatchImportFindingsOutput{
			{SuccessCount: int32Ptr(3), FailedCount: int32Ptr(0)},
		},
	}
	c := &securityHubClient{client: api}

	imported, failed, err := c.BatchImport(t.Context(), findingsN(3))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imported != 3 || failed != 0 {
		t.Errorf("imported = %d, failed = %d, want 3, 0", imported, failed)
	}
	if api.calls != 1 {
		t.Errorf("calls = %d, want 1", api.calls)
	}
}

func TestSecurityHubClient_BatchImport_ChunksAtLimit(t *testing.T) {
	api := &fakeSecurityHubAPI{
		results: []*securityhub.BatchImportFindingsOutput{
			{SuccessCount: int32Ptr(100), FailedCount: int32Ptr(0)},
			{SuccessCount: int32Ptr(50), FailedCount: int32Ptr(0)},
		},
	}
	c := &securityHubClient{client: api}

	imported, failed, err := c.BatchImport(t.Context(), findingsN(150))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if imported != 150 || failed != 0 {
		t.Errorf("imported = %d, failed = %d, want 150, 0", imported, failed)
	}
	if want := []int{100, 50}; !reflect.DeepEqual(api.gotSizes, want) {
		t.Errorf("chunk sizes = %v, want %v", api.gotSizes, want)
	}
}

func TestSecurityHubClient_BatchImport_FailedFindingsAreNotSilenced(t *testing.T) {
	errCode, errMsg, findingID := "InvalidInput", "bad finding", "finding-a"
	api := &fakeSecurityHubAPI{
		results: []*securityhub.BatchImportFindingsOutput{
			{
				SuccessCount: int32Ptr(2),
				FailedCount:  int32Ptr(1),
				FailedFindings: []types.ImportFindingsError{
					{Id: &findingID, ErrorCode: &errCode, ErrorMessage: &errMsg},
				},
			},
		},
	}
	c := &securityHubClient{client: api}

	imported, failed, err := c.BatchImport(t.Context(), findingsN(3))
	if imported != 2 || failed != 1 {
		t.Errorf("imported = %d, failed = %d, want 2, 1", imported, failed)
	}
	if err == nil {
		t.Fatal("expected a non-nil error for a partially failed chunk")
	}
	got := err.Error()
	for _, want := range []string{findingID, errCode, errMsg} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
}

func TestSecurityHubClient_BatchImport_CallErrorIsNotSilenced(t *testing.T) {
	wantErr := errors.New("ThrottlingException")
	api := &fakeSecurityHubAPI{errs: []error{wantErr}}
	c := &securityHubClient{client: api}

	imported, failed, err := c.BatchImport(t.Context(), findingsN(5))
	if imported != 0 || failed != 5 {
		t.Errorf("imported = %d, failed = %d, want 0, 5", imported, failed)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestChunkBy(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		size      int
		wantSizes []int
	}{
		{name: "exact multiple", n: 6, size: 3, wantSizes: []int{3, 3}},
		{name: "remainder", n: 7, size: 3, wantSizes: []int{3, 3, 1}},
		{name: "smaller than chunk size", n: 2, size: 5, wantSizes: []int{2}},
		{name: "empty", n: 0, size: 5, wantSizes: []int{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := chunkBy(findingsN(tt.n), tt.size)

			gotSizes := make([]int, len(chunks))
			for i, c := range chunks {
				gotSizes[i] = len(c)
			}
			if !reflect.DeepEqual(gotSizes, tt.wantSizes) {
				t.Errorf("chunk sizes = %v, want %v", gotSizes, tt.wantSizes)
			}
		})
	}
}
