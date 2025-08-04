package cloudcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type CloudControlGet struct {
	*base.AwsReconLink
}

func NewCloudControlGet(configs ...cfg.Config) chain.Link {
	cc := &CloudControlGet{}
	cc.AwsReconLink = base.NewAwsReconLink(cc, configs...)
	return cc
}

func (c *CloudControlGet) Process(resource *types.EnrichedResourceDescription) error {

	config, err := c.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	client := cloudcontrol.NewFromConfig(config)

	input := &cloudcontrol.GetResourceInput{
		Identifier: &resource.Identifier,
		TypeName:   &resource.TypeName,
	}

	output, err := client.GetResource(context.TODO(), input)
	if err != nil {
		slog.Error("Failed to get resource", "arn", resource.Arn.String(), "error", err)
		return err
	}

	var properties map[string]any
	if err := json.Unmarshal([]byte(*output.ResourceDescription.Properties), &properties); err != nil {
		return fmt.Errorf("failed to unmarshal properties: %w", err)
	}

	enriched := &types.EnrichedResourceDescription{
		Region:     resource.Region,
		TypeName:   *input.TypeName,
		Identifier: *input.Identifier,
		Properties: properties,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	c.Send(enriched)
	return nil
}
