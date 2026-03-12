package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cf "github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSCloudFrontS3TakeoverModule{})
}

type CloudFrontS3TakeoverConfig struct {
	plugin.AWSCommonRecon
}

type AWSCloudFrontS3TakeoverModule struct {
	CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) ID() string                { return "cloudfront-s3-takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Name() string              { return "CloudFront S3 Origin Takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSCloudFrontS3TakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSCloudFrontS3TakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *AWSCloudFrontS3TakeoverModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSCloudFrontS3TakeoverModule) Description() string {
	return "Detects CloudFront distributions with S3 origins pointing to non-existent buckets, " +
		"which could allow attackers to take over the domain by creating the missing bucket. " +
		"Also identifies Route53 records pointing to vulnerable distributions."
}

func (m *AWSCloudFrontS3TakeoverModule) References() []string {
	return []string{
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
		"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
		"https://github.com/EdOverflow/can-i-take-over-xyz",
	}
}

func (m *AWSCloudFrontS3TakeoverModule) SupportedResourceTypes() []string {
	return []string{"AWS::CloudFront::Distribution"}
}

func (m *AWSCloudFrontS3TakeoverModule) Parameters() any {
	return &m.CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.CloudFrontS3TakeoverConfig

	// CloudFront is a global service — always us-east-1.
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	inputs, err := collectInputs(c.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("collect inputs: %w", err)
	}

	lister := cf.NewLister(cloudfront.NewFromConfig(awsCfg), accountID)
	checker := cf.NewChecker(s3.NewFromConfig(awsCfg), route53.NewFromConfig(awsCfg))

	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[cf.DistributionInfo]()
	pipeline.Pipe(inputPipeline, lister.List, listed)

	findings := pipeline.New[cf.Finding]()
	pipeline.Pipe(listed, checker.Check, findings)

	pipeline.Pipe(findings, buildTakeoverRisk, out)
	return out.Wait()
}

func buildTakeoverRisk(f cf.Finding, out *pipeline.P[model.AurelianModel]) error {
	severity := output.RiskSeverityMedium
	if len(f.Route53Records) > 0 {
		severity = output.RiskSeverityHigh
	}

	affectedDomains := collectAffectedDomains(f.Aliases, f.Route53Records)

	description := fmt.Sprintf(
		"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content.",
		f.DistributionID, f.MissingBucket,
	)
	if len(f.Route53Records) > 0 {
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"Route53 records are actively pointing to this distribution. "+
				"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			f.DistributionID, f.MissingBucket,
			len(affectedDomains), strings.Join(affectedDomains, ", "),
		)
	} else if len(affectedDomains) > 0 {
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"An attacker could create this bucket to serve malicious content on alias domain(s): %s",
			f.DistributionID, f.MissingBucket,
			strings.Join(affectedDomains, ", "),
		)
	}

	ctx, err := json.Marshal(map[string]any{
		"distribution_id":     f.DistributionID,
		"distribution_domain": f.DistributionDomain,
		"missing_bucket":      f.MissingBucket,
		"origin_domain":       f.OriginDomain,
		"origin_id":           f.OriginID,
		"aliases":             f.Aliases,
		"affected_domains":    affectedDomains,
		"route53_records":     f.Route53Records,
		"description":         description,
		"impact": "An attacker could register the missing S3 bucket and serve arbitrary content " +
			"through the CloudFront distribution, enabling subdomain or domain takeover.",
		"recommendation": fmt.Sprintf(
			"1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
				"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
				"3. Update the distribution to point to a different, existing origin.",
			f.DistributionID, f.MissingBucket,
		),
	})
	if err != nil {
		slog.Warn("failed to marshal risk context", "distribution", f.DistributionID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        "cloudfront-s3-takeover",
		Severity:    severity,
		ImpactedARN: f.DistributionID,
		Context:     ctx,
	})
	return nil
}

func collectAffectedDomains(aliases []string, records []cf.Route53Record) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, r := range records {
		if !seen[r.RecordName] {
			seen[r.RecordName] = true
			domains = append(domains, r.RecordName)
		}
	}
	for _, alias := range aliases {
		if !seen[alias] {
			seen[alias] = true
			domains = append(domains, alias)
		}
	}
	return domains
}
