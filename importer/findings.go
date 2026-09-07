// Package importer imports parsed ASFF findings into AWS SecurityHub, across AWS accounts and
// regions.
package importer

import (
	"crypto/sha512"
	"encoding/base64"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// globalRegion is substituted for a finding whose ProductArn carries no region.
const globalRegion = "us-east-1"

// filterFailed returns the findings whose Compliance.Status is neither PASSED nor NOT_AVAILABLE.
func filterFailed(findings []types.AwsSecurityFinding) []types.AwsSecurityFinding {
	filtered := make([]types.AwsSecurityFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.Compliance.Status != "PASSED" && finding.Compliance.Status != "NOT_AVAILABLE" {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// assignUniqueIDs rewrites each finding's Id to include a hash of its first resource's Id, so
// the same finding reported against different resources never collides in SecurityHub.
func assignUniqueIDs(findings []types.AwsSecurityFinding) []types.AwsSecurityFinding {
	for i, finding := range findings {
		uniqueID := *finding.Id + "-" + hashSHA512(*finding.Resources[0].Id)
		findings[i].Id = &uniqueID
	}
	return findings
}

// groupByAccountRegion groups findings by AWS account and region, the region taken from each
// finding's ProductArn. A finding with no region in its ProductArn is assigned globalRegion, and
// its ProductArn is rewritten to match.
func groupByAccountRegion(findings []types.AwsSecurityFinding) map[string]map[string][]types.AwsSecurityFinding {
	grouped := make(map[string]map[string][]types.AwsSecurityFinding)

	for _, finding := range findings {
		accountID := *finding.AwsAccountId

		arnParts := strings.Split(*finding.ProductArn, ":")
		region := arnParts[3]
		if region == "" {
			region = globalRegion
			arnParts[3] = globalRegion
			joined := strings.Join(arnParts, ":")
			finding.ProductArn = &joined
		}

		if grouped[accountID] == nil {
			grouped[accountID] = make(map[string][]types.AwsSecurityFinding)
		}
		grouped[accountID][region] = append(grouped[accountID][region], finding)
	}

	return grouped
}

// hashSHA512 returns a short, deterministic identifier for input: the first 9 bytes of its
// SHA-512 hash, base64-encoded.
func hashSHA512(input string) string {
	sum := sha512.Sum512([]byte(input))
	return base64.StdEncoding.EncodeToString(sum[:9])
}
