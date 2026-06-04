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
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

func init() {
	mustRegister("CNAME", "eb-takeover", checkEB)
}

// ebCNAMEPattern matches Elastic Beanstalk CNAME targets.
// Captures: [1] prefix, [2] region
var ebCNAMEPattern = regexp.MustCompile(`^([a-zA-Z0-9-]+)\.((?:[a-z]{2}(?:-[a-z]+)+-\d+))\.elasticbeanstalk\.com\.?$`)

var ebReferences = []string{
	"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
	"https://hackerone.com/reports/473888",
}

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

		risk, err := NewTakeoverRisk(takeoverFinding{
			riskName:  "Elastic Beanstalk Subdomain Takeover",
			severity:  output.RiskSeverityHigh,
			rec:       rec,
			accountID: ctx.AccountID,
			summary: fmt.Sprintf(
				"Route53 CNAME %q points to unclaimed EB prefix %q in %s. "+
					"An attacker can register this prefix and serve arbitrary content.",
				rec.RecordName, prefix, region,
			),
			detailRows: []capmodel.ProofKeyValueRow{
				{Key: "CNAME Target", Value: val, Copyable: true},
				{Key: "EB Prefix", Value: prefix, Copyable: true},
				{Key: "EB Region", Value: region},
			},
			impact: "An attacker who registers the unclaimed Elastic Beanstalk prefix gains control of the " +
				"subdomain and can serve arbitrary content to its visitors.",
			recommendation: []string{
				"Remove the stale CNAME record or recreate the EB environment with the original prefix.",
			},
			references: ebReferences,
		})
		if err != nil {
			slog.Warn("failed to build takeover risk", "record", rec.RecordName, "error", err)
			continue
		}
		out.Send(risk)
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
