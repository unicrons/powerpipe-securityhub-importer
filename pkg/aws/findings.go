package aws

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/unicrons/powerpipe-securityhub-importer/pkg/utils"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	log "github.com/sirupsen/logrus"
)

const globalRegion = "us-east-1"

// convert findings from asff json to types.AwsSecurityFinding
func readFindings(findingsPath string) ([]types.AwsSecurityFinding, error) {
	content, err := os.ReadFile(findingsPath)
	if err != nil {
		log.Fatal("error when opening file: ", err)
	}

	var findings []types.AwsSecurityFinding

	err = json.Unmarshal(content, &findings)
	if err != nil {
		log.Fatal("error during unmarshal: ", err)
	}

	log.Debug("number of findings: ", len(findings))

	return findings, nil
}

// filter Compliance.Status 'PASSED' & NOT_AVAILABLE findings
func filterFindings(findings []types.AwsSecurityFinding) ([]types.AwsSecurityFinding, error) {
	log.Debug("filtering findings because -failed flag was specified")

	var filteredFindings []types.AwsSecurityFinding

	for _, finding := range findings {
		if finding.Compliance.Status != "PASSED" && finding.Compliance.Status != "NOT_AVAILABLE" {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	log.Debug("filtered findings number: ", len(findings)-len(filteredFindings))
	log.Debug("findings after filter: ", len(filteredFindings))

	return filteredFindings, nil
}

// modify finding.Id to generate an unique finding id
func generateUniqueFindingId(findings []types.AwsSecurityFinding) ([]types.AwsSecurityFinding, error) {
	for index, finding := range findings {
		hashedString := utils.HashSha512(*finding.Resources[0].Id)
		uniqueId := *finding.Id + "-" + hashedString
		findings[index].Id = &uniqueId
	}

	// log all findings id
	if log.IsLevelEnabled(log.DebugLevel) {
		for _, finding := range findings {
			log.Debug("finding id: ", *finding.Id)
		}
	}

	return findings, nil
}

// group findings by account and region
func groupFindings(findings []types.AwsSecurityFinding) (map[string]map[string][]types.AwsSecurityFinding, error) {

	groupedFindings := make(map[string]map[string][]types.AwsSecurityFinding)
	for _, finding := range findings {
		accountID := *finding.AwsAccountId

		productArnSplitted := strings.Split(*finding.ProductArn, ":")
		region := productArnSplitted[3]

		if region == "" {
			log.Debugf("empty region in ProductArn: %s, using global region", *finding.ProductArn)

			region = globalRegion
			productArnSplitted[3] = globalRegion
			*finding.ProductArn = strings.Join(productArnSplitted, ":")
		}

		if _, ok := groupedFindings[accountID]; !ok {
			groupedFindings[accountID] = make(map[string][]types.AwsSecurityFinding)
		}

		groupedFindings[accountID][region] = append(groupedFindings[accountID][region], finding)
	}

	// log grouped findings
	if log.IsLevelEnabled(log.DebugLevel) {
		for accountId, regions := range groupedFindings {
			for region, findings := range regions {
				for _, finding := range findings {
					log.Debugf("findings for account: %s, region: %s, id: %s", accountId, region, *finding.Id)
				}
			}
		}
	}

	return groupedFindings, nil
}
