package ebtakeover

import (
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Scan is the main entry point for the EB subdomain takeover scanner.
// It enumerates Route53 CNAME records pointing to EB environments, validates
// which prefixes are unclaimed, and returns Risk findings for each.
func Scan(opts ScanOptions) ([]output.Risk, error) {
	// Resolve account ID if not already provided.
	accountID := opts.AccountID
	if accountID == "" {
		cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     "us-east-1",
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			return nil, fmt.Errorf("create config for account lookup: %w", err)
		}
		accountID, err = awshelpers.GetAccountId(cfg)
		if err != nil {
			return nil, fmt.Errorf("get account id: %w", err)
		}
		slog.Info("resolved account id", "account_id", accountID)
	}

	slog.Info("scanning route53 for elastic beanstalk cname candidates")
	candidates, err := FindEBCandidates(opts.Profile, opts.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("find eb candidates: %w", err)
	}
	slog.Info("found eb cname candidates", "count", len(candidates))

	if len(candidates) == 0 {
		return nil, nil
	}

	slog.Info("validating candidates against elastic beanstalk dns availability api")
	dangling, err := ValidateCandidates(candidates, opts)
	if err != nil {
		return nil, fmt.Errorf("validate candidates: %w", err)
	}
	slog.Info("found dangling records", "count", len(dangling))

	risks := make([]output.Risk, 0, len(dangling))
	for _, d := range dangling {
		risks = append(risks, d.ToRisk(accountID))
	}

	return risks, nil
}
