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

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"golang.org/x/sync/errgroup"
)

// Scan performs CDK bucket takeover vulnerability detection.
func Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
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

	regions := opts.Regions
	if len(regions) == 0 {
		regions = []string{"us-east-1", "us-west-2", "us-east-2", "eu-west-1"}
	}

	qualifiers := opts.Qualifiers
	if len(qualifiers) == 0 {
		qualifiers = []string{"hnb659fds"}
	}

	slog.Info("cdk scan started", "account", accountID, "regions", regions, "qualifiers", qualifiers)

	// Discover additional qualifiers from each region
	for _, region := range regions {
		slog.Debug("discovering qualifiers", "region", region)
		regionCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
			Region:     region,
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			slog.Debug("failed to create region config for qualifier discovery", "region", region, "error", err)
			continue
		}
		ssmClient := ssm.NewFromConfig(regionCfg)
		iamClient := iam.NewFromConfig(regionCfg)
		discovered := discoverQualifiers(ctx, ssmClient, iamClient, accountID, region)
		for _, q := range discovered {
			if !slices.Contains(qualifiers, q) {
				slog.Debug("discovered new qualifier", "qualifier", q, "region", region)
				qualifiers = append(qualifiers, q)
			}
		}
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	limiter := ratelimit.NewAWSRegionLimiter(concurrency)

	var (
		mu       sync.Mutex
		allRoles []RoleInfo
		allRisks []output.Risk
	)

	g, ctx := errgroup.WithContext(ctx)
	for _, region := range regions {
		g.Go(func() error {
			release, err := limiter.Acquire(ctx, region)
			if err != nil {
				return nil
			}
			defer release()

			slog.Info("scanning region", "region", region)

			regionCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
				Region:     region,
				Profile:    opts.Profile,
				ProfileDir: opts.ProfileDir,
			})
			if err != nil {
				return nil
			}

			iamClient := iam.NewFromConfig(regionCfg)
			ssmClient := ssm.NewFromConfig(regionCfg)
			s3Client := s3.NewFromConfig(regionCfg)

			roles := detectRolesInRegion(ctx, iamClient, accountID, region, qualifiers)
			slog.Debug("detected CDK roles", "region", region, "count", len(roles))

			var regionRisks []output.Risk
			for _, role := range roles {
				bootstrapInfo := checkBootstrapVersion(ctx, ssmClient, accountID, region, role.Qualifier)
				if risk := generateBootstrapRisk(role, bootstrapInfo); risk != nil {
					slog.Debug("risk found", "name", risk.Name, "region", region)
					regionRisks = append(regionRisks, *risk)
				}

				if risk := validateBucket(ctx, s3Client, role); risk != nil {
					slog.Debug("risk found", "name", risk.Name, "region", region)
					regionRisks = append(regionRisks, *risk)
				}

				if risk := analyzePolicies(ctx, iamClient, role); risk != nil {
					slog.Debug("risk found", "name", risk.Name, "region", region)
					regionRisks = append(regionRisks, *risk)
				}
			}

			mu.Lock()
			allRoles = append(allRoles, roles...)
			allRisks = append(allRisks, regionRisks...)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	slog.Info("cdk scan complete", "roles", len(allRoles), "risks", len(allRisks))

	return &ScanResult{
		Risks:     allRisks,
		AccountID: accountID,
		Roles:     allRoles,
	}, nil
}
