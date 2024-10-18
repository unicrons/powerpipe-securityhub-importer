package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/unicrons/powerpipe-securityhub-importer/pkg/utils"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	log "github.com/sirupsen/logrus"
)

type OrganizationAccount struct {
	Name      string
	AccountID string
}

const batchImportLimit int = 100 // aws limit

func SecurityHubImportFindings(findingsPath, roleName, sessionName string, onlyFailed bool) error {

	findings, err := readFindings(findingsPath)
	if err != nil {
		return fmt.Errorf("failed to read findings: %w", err)
	}

	if onlyFailed {
		findings, err = filterFindings(findings)
		if err != nil {
			return fmt.Errorf("failed to filter findings: %w", err)
		}
	}

	findings, err = generateUniqueFindingId(findings)
	if err != nil {
		return fmt.Errorf("failed to generate unique finding id: %w", err)
	}

	groupedFindings, err := groupFindings(findings)
	if err != nil {
		return fmt.Errorf("failed to group finding: %w", err)
	}

	ctx := context.Background()
	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("error loading aws config: %w", err)
	}

	sts, err := newStsClient(awscfg)
	if err != nil {
		return fmt.Errorf("error getting sts client: %w", err)
	}

	var wgAccounts sync.WaitGroup
	var wgRegions sync.WaitGroup

	for accountId, regions := range groupedFindings {
		wgAccounts.Add(1)

		// goroutine for each account
		go func(accountId string, regions map[string][]types.AwsSecurityFinding) {
			defer wgAccounts.Done()

			for region, filteredFindings := range regions {
				wgRegions.Add(1)

				// goroutine for each region
				go func(accountId, region string, filteredFindings []types.AwsSecurityFinding) {
					defer wgRegions.Done()

					awscfg, err = getAssumeRoleConfig(sts, accountId, region, roleName, sessionName)
					if err != nil {
						log.Error("error getting aws config:", err)
						return
					}

					sh, err := newSecurityHubClient(awscfg)
					if err != nil {
						log.Error("error getting securityhub client:", err)
						return
					}

					err = sh.batchImportFindings(filteredFindings)
					if err != nil {
						for _, finding := range filteredFindings {
							log.Debugf("finding region: %s, productArn: %s", string(*finding.Region), string(*finding.ProductArn))
						}
						log.Error("error importing securityhub findings: ", err)
						return
					}

				}(accountId, region, filteredFindings)
			}
		}(accountId, regions)
	}

	wgAccounts.Wait()
	wgRegions.Wait()

	return nil
}

func (sh *SecurityHubClient) batchImportFindings(findings []types.AwsSecurityFinding) error {

	if len(findings) <= 0 {
		return fmt.Errorf("no findings received, skipping sending")
	}

	var successCount, failedCount int
	awsFindingChunks := utils.ChunkBy(findings, batchImportLimit)

	log.Debugf("sending %d findings in %d chunk(s) to securityhub", len(findings), len(awsFindingChunks))

	for _, awsfindingChunk := range awsFindingChunks {
		output, err := sh.client.BatchImportFindings(context.Background(), &securityhub.BatchImportFindingsInput{
			Findings: awsfindingChunk,
		})
		if err != nil {
			return fmt.Errorf("failed to import findings to securityhub: %w", err)
		}

		if len(output.FailedFindings) > 0 {
			failedCount += len(output.FailedFindings)
			log.Errorf("%d findings failed to be reported...", len(output.FailedFindings))
			for _, ff := range output.FailedFindings {
				log.Errorf("failed finding details: ID: %s , ErrorCode: %s, ErrorMessage: %s\n", *ff.Id, *ff.ErrorCode, *ff.ErrorMessage)
			}
		}
		successCount += int(*output.SuccessCount)
	}

	log.Debugf("successfully sent: %d findings to securityhub", successCount)
	return nil
}
