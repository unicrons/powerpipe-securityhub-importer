package importer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"golang.org/x/sync/errgroup"

	internalaws "github.com/unicrons/powerpipe-securityhub-importer/internal/aws"
)

// maxConcurrentImports bounds how many account/region imports run at once. There's no single
// shared AWS rate limit to size this against - each account/region uses its own assumed-role
// credentials - so this is a generic guard against unbounded goroutine/connection fan-out for
// organizations with very large account x region counts.
const maxConcurrentImports = 20

// Options configures an Importer.
type Options struct {
	// RoleName is the IAM role assumed in each target account.
	RoleName string
	// SessionName is the STS session name used for each assumed role.
	SessionName string
	// OnlyFailed drops PASSED and NOT_AVAILABLE findings before importing.
	OnlyFailed bool
}

// Result is the aggregate outcome of an Import call.
type Result struct {
	Imported int
	Failed   int
}

// Importer imports parsed ASFF findings into AWS SecurityHub, across AWS accounts and regions.
type Importer interface {
	Import(ctx context.Context, findings []types.AwsSecurityFinding) (Result, error)
}

// SecurityHubBackend assumes a role in one AWS account/region and imports findings there.
// Defined here, where it's consumed - internal/aws.NewSecurityHubBackend returns a real,
// SDK-backed implementation; tests use an in-memory fake instead.
type SecurityHubBackend interface {
	Import(ctx context.Context, accountID, region string, findings []types.AwsSecurityFinding) (imported, failed int, err error)
}

type importer struct {
	backend SecurityHubBackend
	opts    Options
}

// New returns an Importer configured from the default AWS environment.
func New(ctx context.Context, opts Options) (Importer, error) {
	cfg, err := internalaws.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading aws config: %w", err)
	}

	return &importer{
		backend: internalaws.NewSecurityHubBackend(cfg, opts.RoleName, opts.SessionName),
		opts:    opts,
	}, nil
}

// job is one account/region's findings, the unit of work run concurrently by Import.
type job struct {
	accountID string
	region    string
	findings  []types.AwsSecurityFinding
}

// Import groups findings by account/region and imports each group concurrently. Each
// account/region is independent, so one failing doesn't stop the others: every job's outcome is
// aggregated into Result, and every job's error - accountID and region attached, so it's
// identifiable among potentially hundreds - is joined into the single error returned.
func (im *importer) Import(ctx context.Context, findings []types.AwsSecurityFinding) (Result, error) {
	if im.opts.OnlyFailed {
		findings = filterFailed(findings)
	}
	findings = assignUniqueIDs(findings)
	grouped := groupByAccountRegion(findings)

	var jobs []job
	for accountID, byRegion := range grouped {
		for region, fs := range byRegion {
			jobs = append(jobs, job{accountID, region, fs})
		}
	}

	var (
		imported, failed atomic.Int64
		mu               sync.Mutex
		errs             []error
	)

	// errgroup is used only to bound concurrency via SetLimit - its own error-propagation and
	// cancel-on-first-error behavior goes unused, since every job below always returns nil to
	// the group; a job's real error is instead appended to errs directly.
	g := new(errgroup.Group)
	g.SetLimit(maxConcurrentImports)

	for _, j := range jobs {
		g.Go(func() error {
			jobImported, jobFailed, err := im.backend.Import(ctx, j.accountID, j.region, j.findings)
			imported.Add(int64(jobImported))
			failed.Add(int64(jobFailed))

			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("account %s region %s: %w", j.accountID, j.region, err))
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()

	return Result{Imported: int(imported.Load()), Failed: int(failed.Load())}, errors.Join(errs...)
}
