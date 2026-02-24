package nstakeover

import (
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Scan is the main entry point for the NS delegation takeover scanner.
// It enumerates Route53 NS delegation records pointing to Route53 nameservers,
// validates which delegations are dangling (hosted zone gone), and returns
// Risk findings for each confirmed dangling delegation.
func Scan(opts ScanOptions) ([]output.Risk, error) {
	// Step 1: Resolve account ID via STS.
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
		slog.Info("ns-takeover: resolved account", "account_id", accountID)
	}

	// Step 2: Enumerate Route53 NS delegations.
	slog.Info("ns-takeover: enumerating route53 ns delegation records")
	delegations, err := FindNSDelegations(opts.Profile, opts.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("find ns delegations: %w", err)
	}
	slog.Info("ns-takeover: found ns delegation candidates", "count", len(delegations))

	if len(delegations) == 0 {
		return nil, nil
	}

	// Step 3: Validate each delegation via direct DNS query to the nameserver.
	slog.Info("ns-takeover: validating delegations via dns query")
	dangling, err := ValidateDelegations(delegations, opts.Concurrency)
	if err != nil {
		return nil, fmt.Errorf("validate delegations: %w", err)
	}
	slog.Info("ns-takeover: found dangling ns delegations", "count", len(dangling))

	// Step 4: Convert to output.Risk findings.
	risks := make([]output.Risk, 0, len(dangling))
	for _, d := range dangling {
		risks = append(risks, d.ToRisk(accountID))
	}

	return risks, nil
}
