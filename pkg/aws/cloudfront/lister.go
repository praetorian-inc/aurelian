package cloudfront

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	cfclient "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Lister enumerates CloudFront distributions via the pipeline interface.
// It handles both single-distribution ARN input and full enumeration.
type Lister struct {
	cfClient  CloudFrontAPI
	accountID string
}

// NewLister creates a Lister from a pre-configured CloudFront client.
func NewLister(cfClient *cfclient.Client, accountID string) *Lister {
	return &Lister{
		cfClient:  cfClient,
		accountID: accountID,
	}
}

// List routes an identifier to single-distribution fetch or full enumeration.
func (l *Lister) List(identifier string, out *pipeline.P[DistributionInfo]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		return l.listByARN(parsed, out)
	}

	if strings.HasPrefix(identifier, "AWS::") {
		return l.listAll(out)
	}

	return fmt.Errorf("identifier must be an ARN or CloudControl resource type: %q", identifier)
}

func (l *Lister) listByARN(parsed awsaarn.ARN, out *pipeline.P[DistributionInfo]) error {
	distID, err := parseDistributionID(parsed.Resource)
	if err != nil {
		return err
	}

	slog.Debug("fetching single distribution", "id", distID)

	resp, err := l.cfClient.GetDistribution(context.Background(), &cfclient.GetDistributionInput{
		Id: &distID,
	})
	if err != nil {
		return fmt.Errorf("get distribution %s: %w", distID, err)
	}

	info := buildDistributionInfo(resp, l.accountID)
	out.Send(info)
	return nil
}

func (l *Lister) listAll(out *pipeline.P[DistributionInfo]) error {
	slog.Info("enumerating all CloudFront distributions", "account", l.accountID)

	dists, err := enumerateDistributions(context.Background(), l.cfClient, l.accountID)
	if err != nil {
		return fmt.Errorf("enumerate distributions: %w", err)
	}

	slog.Info("found distributions", "count", len(dists))
	for _, d := range dists {
		out.Send(d)
	}
	return nil
}

func parseDistributionID(resource string) (string, error) {
	prefix := "distribution/"
	after, found := strings.CutPrefix(resource, prefix)
	if !found || after == "" {
		return "", fmt.Errorf("invalid CloudFront ARN resource %q: expected %s<id>", resource, prefix)
	}
	return after, nil
}
