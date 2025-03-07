package aws

import (
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type ResourceProcessor struct {
	*chain.Base
}

func NewResourceProcessor() chain.Link {
	rp := &ResourceProcessor{}
	rp.Base = chain.NewBase(rp)
	return rp
}

func (rp *ResourceProcessor) Process(resource *types.EnrichedResourceDescription) error {
	// Parse ARN from identifier first
	parsed, err := arn.Parse(resource.Identifier)
	if err != nil {
		slog.Debug("failed to parse ARN",
			"identifier", resource.Identifier,
			"error", err)
		resource.Arn = resource.ToArn()
	} else {
		slog.Debug("parsed ARN",
			"identifier", resource.Identifier,
			"arn", parsed.String())
		resource.Arn = parsed
	}

	// Always set the canonical ARN
	resource.Arn = resource.ToArn()

	rp.Send(resource)
	return nil
}
