package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	log "github.com/sirupsen/logrus"
)

func (sts *StsClient) assumeRole(role, sessionName string) (aws.Credentials, error) {

	appCreds := stscreds.NewAssumeRoleProvider(sts.client, role, func(opts *stscreds.AssumeRoleOptions) {
		opts.RoleSessionName = sessionName
	})
	value, err := appCreds.Retrieve(context.Background())
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("assume role failed: %w", err)
	}

	log.Debugf("successfully generated sts credentials for role: %s", role)

	return value, err
}

func getAssumeRoleConfig(sts *StsClient, accountId, region, roleName, sessionName string) (aws.Config, error) {

	ctx := context.Background()

	// Assume role for each account
	creds, err := sts.assumeRole("arn:aws:iam::"+accountId+":role/"+roleName, sessionName)
	if err != nil {
		return aws.Config{}, fmt.Errorf("error assuming role: %s", err)
	}

	// Getting AWS client config for each account
	awscfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.AccessKeyID,
				creds.SecretAccessKey,
				creds.SessionToken,
			),
		),
		config.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("error loading aws config: %s", err)
	}

	log.Debugf("successfully generated assume role config for: %s, %s, %s, %s", accountId, region, roleName, sessionName)

	return awscfg, nil
}
