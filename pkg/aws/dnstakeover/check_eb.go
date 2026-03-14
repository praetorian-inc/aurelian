package dnstakeover

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "eb-takeover", checkEB)
}

// ebCNAMEPattern matches Elastic Beanstalk CNAME targets.
// Captures: [1] prefix, [2] region
var ebCNAMEPattern = regexp.MustCompile(`^([a-zA-Z0-9-]+)\.((?:[a-z]{2}(?:-[a-z]+)+-\d+))\.elasticbeanstalk\.com\.?$`)

func checkEB(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		m := ebCNAMEPattern.FindStringSubmatch(val)
		if m == nil {
			continue
		}

		prefix, region := m[1], m[2]

		available, err := checkEBDNSAvailability(ctx, prefix, region)
		if err != nil {
			slog.Warn("eb dns availability check failed",
				"record", rec.RecordName,
				"prefix", prefix,
				"region", region,
				"error", err,
			)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"eb-subdomain-takeover",
			output.RiskSeverityHigh,
			rec,
			ctx.AccountID,
			map[string]any{
				"cname_target": val,
				"eb_prefix":    prefix,
				"eb_region":    region,
				"description": fmt.Sprintf(
					"Route53 CNAME %q points to unclaimed EB prefix %q in %s. "+
						"An attacker can register this prefix and serve arbitrary content.",
					rec.RecordName, prefix, region,
				),
				"recommendation": "Remove the stale CNAME record or recreate the EB environment with the original prefix.",
				"references": []string{
					"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
					"https://hackerone.com/reports/473888",
				},
			},
		))
	}

	return nil
}

func checkEBDNSAvailability(ctx CheckContext, prefix, region string) (bool, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    ctx.Opts.Profile,
		ProfileDir: ctx.Opts.ProfileDir,
	})
	if err != nil {
		return false, fmt.Errorf("create eb config for region %s: %w", region, err)
	}

	client := elasticbeanstalk.NewFromConfig(cfg)
	resp, err := client.CheckDNSAvailability(ctx.Ctx, &elasticbeanstalk.CheckDNSAvailabilityInput{
		CNAMEPrefix: aws.String(prefix),
	})
	if err != nil {
		return false, err
	}

	if resp.Available == nil {
		return false, nil
	}
	return *resp.Available, nil
}
