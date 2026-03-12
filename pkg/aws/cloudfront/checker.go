package cloudfront

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Checker validates CloudFront distributions for S3 origin takeover vulnerabilities.
type Checker struct {
	s3Client  S3API
	r53Client Route53API
}

// NewChecker creates a Checker from pre-configured S3 and Route53 clients.
func NewChecker(s3Client *s3.Client, r53Client *route53.Client) *Checker {
	return &Checker{
		s3Client:  s3Client,
		r53Client: r53Client,
	}
}

// Check validates a single distribution's S3 origins and emits a Finding for each missing bucket.
func (c *Checker) Check(dist DistributionInfo, out *pipeline.P[Finding]) error {
	vulnerable := checkDistributionOrigins(context.Background(), c.s3Client, dist)

	for _, vuln := range vulnerable {
		records, err := findRoute53Records(context.Background(), c.r53Client, vuln.DistributionDomain, vuln.Aliases)
		if err != nil {
			slog.Warn("error searching Route53 records", "distribution", vuln.DistributionID, "error", err)
			records = nil
		}

		out.Send(Finding{
			VulnerableDistribution: vuln,
			Route53Records:         records,
		})
	}

	return nil
}
