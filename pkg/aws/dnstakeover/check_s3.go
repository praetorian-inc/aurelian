package dnstakeover

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "s3-website-takeover", checkS3)
	mustRegister("A", "s3-website-takeover", checkS3)
	mustRegister("AAAA", "s3-website-takeover", checkS3)
}

// s3WebsiteEndpointPattern matches regional S3 website alias targets that do
// not include the bucket name (the record FQDN is the bucket).
var s3WebsiteEndpointPattern = regexp.MustCompile(`^s3-website[-.](?:dualstack\.)?[a-z0-9-]+\.amazonaws\.com$`)

func checkS3(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    ctx.Opts.Profile,
		ProfileDir: ctx.Opts.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create s3 config: %w", err)
	}
	return checkS3WithClient(ctx, s3.NewFromConfig(cfg), rec, out)
}

func checkS3WithClient(ctx CheckContext, client cloudfront.S3API, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	bucket, ok := s3BucketFromRecord(rec)
	if !ok {
		return nil
	}

	existence := cloudfront.CheckBucketExists(ctx.Ctx, client, bucket)
	if existence != cloudfront.BucketNotExists {
		if existence == cloudfront.BucketUnknown {
			slog.Warn("s3 website existence unknown", "bucket", bucket, "record", rec.RecordName)
		}
		return nil
	}

	out.Send(NewTakeoverRisk(
		"s3-website-subdomain-takeover",
		output.RiskSeverityHigh,
		rec,
		ctx.AccountID,
		map[string]any{
			"service":      "S3 website",
			"cname_target": strings.Join(rec.Values, ","),
			"bucket_name":  bucket,
			"description": fmt.Sprintf(
				"Route53 %s %q points to missing S3 bucket %q. An attacker can create the bucket and serve content.",
				rec.Type, rec.RecordName, bucket,
			),
			"recommendation": "Remove the stale record or recreate the bucket. Do not leave website CNAMEs/aliases dangling.",
			"references": []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html",
				"https://arxiv.org/abs/2403.19368",
			},
		},
	))
	return nil
}

func s3BucketFromRecord(rec Route53Record) (string, bool) {
	for _, val := range rec.Values {
		host := strings.TrimSuffix(val, ".")
		// ExtractBucketName's fallback keys on substring ".s3" and will
		// return a bucket for non-AWS hosts (e.g. files.s3.internal.example.com).
		if strings.HasSuffix(host, ".amazonaws.com") {
			if bucket := cloudfront.ExtractBucketName(host); bucket != "" {
				return bucket, true
			}
		}
		if rec.IsAlias && s3WebsiteEndpointPattern.MatchString(host) {
			name := strings.TrimSuffix(rec.RecordName, ".")
			if name != "" {
				return name, true
			}
		}
	}
	return "", false
}
