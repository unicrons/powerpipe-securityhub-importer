package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"
)

type StsClient struct {
	client *sts.Client
}

type SecurityHubClient struct {
	client *securityhub.Client
}

func newStsClient(awscfg aws.Config) (*StsClient, error) {
	client := sts.NewFromConfig(awscfg)
	return &StsClient{client: client}, nil
}

func newSecurityHubClient(awscfg aws.Config) (*SecurityHubClient, error) {
	client := securityhub.NewFromConfig(awscfg)

	log.Debug("securityhub client region: ", client.Options().Region)

	return &SecurityHubClient{client: client}, nil
}
