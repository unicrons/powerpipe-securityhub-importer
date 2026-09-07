package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// SecurityHubBackend assumes a role in one AWS account/region and imports findings there. It
// implicitly satisfies the importer package's SecurityHubBackend interface - not referenced
// here directly, to avoid internal/aws importing the package that consumes it.
type SecurityHubBackend struct {
	stsClient   stscreds.AssumeRoleAPIClient
	roleName    string
	sessionName string
}

// NewSecurityHubBackend returns a backend that assumes roleName in each target account, using
// cfg's credentials to call AssumeRole.
func NewSecurityHubBackend(cfg aws.Config, roleName, sessionName string) *SecurityHubBackend {
	return &SecurityHubBackend{
		stsClient:   sts.NewFromConfig(cfg),
		roleName:    roleName,
		sessionName: sessionName,
	}
}

// Import assumes b.roleName in accountID/region, then imports findings there. Each call builds
// its own config and client from local variables, so concurrent calls for different
// accounts/regions never share mutable state.
func (b *SecurityHubBackend) Import(ctx context.Context, accountID, region string, findings []types.AwsSecurityFinding) (imported, failed int, err error) {
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, b.roleName)

	cfg, err := AssumeRoleConfig(ctx, b.stsClient, roleArn, b.sessionName, region)
	if err != nil {
		return 0, 0, fmt.Errorf("account %s: assuming role: %w", accountID, err)
	}

	return NewSecurityHubClient(cfg).BatchImport(ctx, findings)
}
