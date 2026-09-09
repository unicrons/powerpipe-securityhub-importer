package importer

import (
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func strPtr(s string) *string { return &s }

func findingWith(id, accountID, productArn string, status types.ComplianceStatus, resourceID string) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{
		Id:           strPtr(id),
		AwsAccountId: strPtr(accountID),
		ProductArn:   strPtr(productArn),
		Compliance:   &types.Compliance{Status: status},
		Resources:    []types.Resource{{Id: strPtr(resourceID)}},
	}
}

func TestFilterFailed(t *testing.T) {
	tests := []struct {
		name   string
		status types.ComplianceStatus
		want   bool
	}{
		{name: "passed is excluded", status: "PASSED", want: false},
		{name: "not_available is excluded", status: "NOT_AVAILABLE", want: false},
		{name: "failed is kept", status: "FAILED", want: true},
		{name: "warning is kept", status: "WARNING", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []types.AwsSecurityFinding{
				findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", tt.status, "res-1"),
			}

			got := filterFailed(findings)
			if (len(got) == 1) != tt.want {
				t.Errorf("filterFailed() kept %d findings for status %q, want kept = %v", len(got), tt.status, tt.want)
			}
		})
	}
}

func TestAssignUniqueIDs(t *testing.T) {
	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-2"),
	}

	got := assignUniqueIDs(findings)

	wantFirst := "id-1-" + hashSHA512("res-1")
	if *got[0].Id != wantFirst {
		t.Errorf("got[0].Id = %q, want %q", *got[0].Id, wantFirst)
	}

	wantSecond := "id-1-" + hashSHA512("res-2")
	if *got[1].Id != wantSecond {
		t.Errorf("got[1].Id = %q, want %q", *got[1].Id, wantSecond)
	}

	if *got[0].Id == *got[1].Id {
		t.Error("findings with the same base Id but different resources ended up with the same unique Id")
	}
}

func TestGroupByAccountRegion(t *testing.T) {
	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
		findingWith("id-2", "111111111111", "arn:aws:securityhub:eu-west-1::product/test/test", "FAILED", "res-2"),
		findingWith("id-3", "222222222222", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-3"),
	}

	grouped := groupByAccountRegion(findings)

	if len(grouped) != 2 {
		t.Fatalf("got %d accounts, want 2: %+v", len(grouped), grouped)
	}
	if len(grouped["111111111111"]["us-east-1"]) != 1 || len(grouped["111111111111"]["eu-west-1"]) != 1 {
		t.Errorf("account 111111111111 regions = %+v, want one finding each in us-east-1 and eu-west-1", grouped["111111111111"])
	}
	if len(grouped["222222222222"]["us-east-1"]) != 1 {
		t.Errorf("account 222222222222 regions = %+v, want one finding in us-east-1", grouped["222222222222"])
	}
}

func TestGroupByAccountRegion_EmptyRegionFallsBackToGlobal(t *testing.T) {
	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:::product/test/test", "FAILED", "res-1"),
	}

	grouped := groupByAccountRegion(findings)

	got, ok := grouped["111111111111"][globalRegion]
	if !ok || len(got) != 1 {
		t.Fatalf("grouped[111111111111] = %+v, want one finding under %q", grouped["111111111111"], globalRegion)
	}

	want := "arn:aws:securityhub:" + globalRegion + "::product/test/test"
	if *got[0].ProductArn != want {
		t.Errorf("ProductArn = %q, want %q", *got[0].ProductArn, want)
	}
}

func TestGroupByAccountRegion_BackfillsMissingResourceRegion(t *testing.T) {
	findings := []types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
	}

	grouped := groupByAccountRegion(findings)

	got := grouped["111111111111"]["us-east-1"][0].Resources[0].Region
	if got == nil || *got != "us-east-1" {
		t.Errorf("Resources[0].Region = %v, want %q", got, "us-east-1")
	}
}

func TestGroupByAccountRegion_PreservesExistingResourceRegion(t *testing.T) {
	finding := findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1")
	finding.Resources[0].Region = strPtr("eu-west-1")

	grouped := groupByAccountRegion([]types.AwsSecurityFinding{finding})

	got := grouped["111111111111"]["us-east-1"][0].Resources[0].Region
	if got == nil || *got != "eu-west-1" {
		t.Errorf("Resources[0].Region = %v, want the pre-existing %q preserved", got, "eu-west-1")
	}
}

func TestHashSHA512(t *testing.T) {
	a := hashSHA512("res-1")
	b := hashSHA512("res-1")
	c := hashSHA512("res-2")

	if a != b {
		t.Error("hashSHA512 is not deterministic for the same input")
	}
	if a == c {
		t.Error("hashSHA512 returned the same output for different inputs")
	}
	if len(a) != 12 {
		t.Errorf("len(hashSHA512(...)) = %d, want 12 (base64 of 9 bytes)", len(a))
	}
}

func TestGroupByAccountRegion_PreservesFindings(t *testing.T) {
	findings := assignUniqueIDs([]types.AwsSecurityFinding{
		findingWith("id-1", "111111111111", "arn:aws:securityhub:us-east-1::product/test/test", "FAILED", "res-1"),
	})

	grouped := groupByAccountRegion(findings)
	got := grouped["111111111111"]["us-east-1"]

	if !slices.ContainsFunc(got, func(f types.AwsSecurityFinding) bool { return *f.Id == *findings[0].Id }) {
		t.Errorf("grouped findings %+v do not contain the expected finding %+v", got, findings[0])
	}
}
