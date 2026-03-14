// Package cdk provides CDK bucket takeover vulnerability detection.
//
// It implements a pipeline that discovers CDK qualifiers, detects bootstrap roles,
// checks bootstrap versions, validates S3 bucket ownership, and analyzes IAM
// policies for missing account restrictions.
package cdk

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"golang.org/x/sync/errgroup"
)

// Scanner holds shared state for a CDK bucket takeover scan.
type Scanner struct {
	opts      ScanOptions
	accountID string
	regions   []string
	limiter   *ratelimit.AWSRegionLimiter
	emit      func(output.Risk)

	mu       sync.Mutex
	allRoles []RoleInfo
}

func newScanner(opts ScanOptions) (*Scanner, error) {
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	regions, err := helpers.ResolveRegions(opts.Regions, opts.Profile, opts.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	concurrency := max(opts.Concurrency, 1)
	emit := opts.OnRisk
	if emit == nil {
		emit = func(output.Risk) {}
	}

	return &Scanner{
		opts:      opts,
		accountID: accountID,
		regions:   regions,
		limiter:   ratelimit.NewAWSRegionLimiter(concurrency),
		emit:      emit,
	}, nil
}

func (s *Scanner) regionConfig(region string) (aws.Config, error) {
	return helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     region,
		Profile:    s.opts.Profile,
		ProfileDir: s.opts.ProfileDir,
	})
}

// Scan performs CDK bucket takeover vulnerability detection.
func Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	s, err := newScanner(opts)
	if err != nil {
		return nil, err
	}

	slog.Info("cdk scan started", "account", s.accountID, "regions", s.regions, "qualifiers", s.opts.Qualifiers)

	if err := s.discoverQualifiers(ctx); err != nil {
		return nil, fmt.Errorf("qualifier discovery: %w", err)
	}

	return s.scan(ctx)
}

func (s *Scanner) discoverQualifiers(ctx context.Context) error {
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	for _, region := range s.regions {
		g.Go(func() error {
			return s.discoverInRegion(ctx, region, &mu)
		})
	}

	return g.Wait()
}

func (s *Scanner) discoverInRegion(ctx context.Context, region string, mu *sync.Mutex) error {
	release, err := s.limiter.Acquire(ctx, region)
	if err != nil {
		return err
	}
	defer release()

	slog.Debug("discovering qualifiers", "region", region)
	regionCfg, err := s.regionConfig(region)
	if err != nil {
		slog.Warn("skipping qualifier discovery", "region", region, "error", err)
		return nil
	}

	ssmClient := ssm.NewFromConfig(regionCfg)
	iamClient := iam.NewFromConfig(regionCfg)
	discovered := discoverQualifiers(ctx, ssmClient, iamClient, s.accountID, region)

	mu.Lock()
	for _, q := range discovered {
		if !slices.Contains(s.opts.Qualifiers, q) {
			slog.Debug("discovered new qualifier", "qualifier", q, "region", region)
			s.opts.Qualifiers = append(s.opts.Qualifiers, q)
		}
	}
	mu.Unlock()

	return nil
}

func (s *Scanner) scan(ctx context.Context) (*ScanResult, error) {
	g, ctx := errgroup.WithContext(ctx)

	for _, region := range s.regions {
		g.Go(func() error {
			return s.scanRegion(ctx, region)
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	slog.Info("cdk scan complete", "roles", len(s.allRoles))

	return &ScanResult{
		AccountID: s.accountID,
		Roles:     s.allRoles,
	}, nil
}

func (s *Scanner) scanRegion(ctx context.Context, region string) error {
	release, err := s.limiter.Acquire(ctx, region)
	if err != nil {
		return err
	}
	defer release()

	slog.Info("scanning region", "region", region)

	regionCfg, err := s.regionConfig(region)
	if err != nil {
		slog.Warn("skipping region scan", "region", region, "error", err)
		return nil
	}

	iamClient := iam.NewFromConfig(regionCfg)
	ssmClient := ssm.NewFromConfig(regionCfg)
	s3Client := s3.NewFromConfig(regionCfg)

	roles := detectRolesInRegion(ctx, iamClient, s.accountID, region, s.opts.Qualifiers)
	slog.Debug("detected CDK roles", "region", region, "count", len(roles))

	processRegionRoles(roles,
		func(role RoleInfo) *output.Risk {
			info := checkBootstrapVersion(ctx, ssmClient, s.accountID, region, role.Qualifier)
			return generateBootstrapRisk(role, info)
		},
		func(role RoleInfo) *output.Risk { return validateBucket(ctx, s3Client, role) },
		func(role RoleInfo) *output.Risk { return analyzePolicies(ctx, iamClient, role) },
		s.emit,
	)

	s.mu.Lock()
	s.allRoles = append(s.allRoles, roles...)
	s.mu.Unlock()

	return nil
}

// processRegionRoles groups roles by qualifier and runs per-qualifier checks
// (bootstrap, bucket) once per qualifier and per-role checks (policy) for each role.
func processRegionRoles(
	roles []RoleInfo,
	checkBootstrap func(RoleInfo) *output.Risk,
	checkBucket func(RoleInfo) *output.Risk,
	checkPolicy func(RoleInfo) *output.Risk,
	emit func(output.Risk),
) {
	byQualifier := make(map[string][]RoleInfo)
	for _, role := range roles {
		byQualifier[role.Qualifier] = append(byQualifier[role.Qualifier], role)
	}

	for _, qualifierRoles := range byQualifier {
		if risk := checkBootstrap(qualifierRoles[0]); risk != nil {
			emit(*risk)
		}
		if risk := checkBucket(qualifierRoles[0]); risk != nil {
			emit(*risk)
		}
		for _, role := range qualifierRoles {
			if risk := checkPolicy(role); risk != nil {
				emit(*risk)
			}
		}
	}
}
