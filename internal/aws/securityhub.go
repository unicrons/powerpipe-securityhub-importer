package aws

import (
	"context"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// batchImportLimit is the AWS SecurityHub BatchImportFindings API's own limit on findings per call.
const batchImportLimit = 100

// securityHubAPI is the subset of the AWS SecurityHub SDK client this package calls.
type securityHubAPI interface {
	BatchImportFindings(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error)
}

type securityHubClient struct {
	client securityHubAPI
}

// NewSecurityHubClient returns a client backed by the real AWS SDK, using cfg's region and
// credentials.
func NewSecurityHubClient(cfg awssdk.Config) *securityHubClient {
	return &securityHubClient{client: securityhub.NewFromConfig(cfg)}
}

// BatchImport sends findings to SecurityHub in chunks of at most batchImportLimit, and returns
// how many were imported and how many failed. A non-nil error joins every failure - both a
// chunk's own call error and each finding SecurityHub itself rejected (FailedFindings) - so
// nothing is dropped silently.
func (c *securityHubClient) BatchImport(ctx context.Context, findings []types.AwsSecurityFinding) (imported, failed int, err error) {
	if len(findings) == 0 {
		return 0, 0, nil
	}

	var errs []error

	for _, chunk := range chunkBy(findings, batchImportLimit) {
		output, callErr := c.client.BatchImportFindings(ctx, &securityhub.BatchImportFindingsInput{
			Findings: chunk,
		})
		if callErr != nil {
			failed += len(chunk)
			errs = append(errs, fmt.Errorf("importing %d findings: %w", len(chunk), callErr))
			continue
		}

		imported += int(*output.SuccessCount)
		failed += len(output.FailedFindings)
		for _, ff := range output.FailedFindings {
			errs = append(errs, fmt.Errorf("finding %s: %s (%s)", *ff.Id, *ff.ErrorMessage, *ff.ErrorCode))
		}
	}

	return imported, failed, errors.Join(errs...)
}

// chunkBy splits items into chunks of at most chunkSize elements each.
func chunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}
