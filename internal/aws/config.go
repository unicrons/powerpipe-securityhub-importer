// Package aws wraps the AWS SDK calls this tool needs: loading the local default config,
// assuming a role in a target account/region, and importing findings into SecurityHub there.
package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
)

// LoadDefaultConfig returns an AWS SDK config resolved from the local environment (env vars,
// shared config/credentials files, EC2/ECS metadata, etc.) - the credentials used to assume a
// role in each target account.
func LoadDefaultConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading aws config: %w", err)
	}
	return cfg, nil
}

// AssumeRoleConfig assumes roleArn via client and returns an AWS SDK config for region, using
// the resulting temporary credentials.
func AssumeRoleConfig(ctx context.Context, client stscreds.AssumeRoleAPIClient, roleArn, sessionName, region string) (aws.Config, error) {
	creds, err := assumeRole(ctx, client, roleArn, sessionName)
	if err != nil {
		return aws.Config{}, fmt.Errorf("assuming role %s: %w", roleArn, err)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
		)),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading aws config for assumed role: %w", err)
	}

	return cfg, nil
}

// assumeRole retrieves temporary credentials for roleArn. client only needs to implement the
// SDK's own stscreds.AssumeRoleAPIClient interface, not the concrete *sts.Client, so tests can
// fake the AssumeRole call without any network access.
func assumeRole(ctx context.Context, client stscreds.AssumeRoleAPIClient, roleArn, sessionName string) (aws.Credentials, error) {
	provider := stscreds.NewAssumeRoleProvider(client, roleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
	})

	creds, err := provider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("retrieving assumed role credentials: %w", err)
	}
	return creds, nil
}
