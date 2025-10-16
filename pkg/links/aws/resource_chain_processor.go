package aws

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AWSResourceChainProcessor processes ResourceChainPair objects concurrently
type AWSResourceChainProcessor struct {
	*base.AwsReconLink
}

type ResourceChainPair struct {
	Resource         *types.EnrichedResourceDescription
	ChainConstructor func() chain.Chain
	Args             map[string]any
}

func NewAWSResourceChainProcessor(configs ...cfg.Config) chain.Link {
	p := &AWSResourceChainProcessor{}
	p.AwsReconLink = base.NewAwsReconLink(p, configs...)
	return p
}

func (p *AWSResourceChainProcessor) Process(pair *ResourceChainPair) error {
	slog.Debug("Processing resource chain",
		"resource_type", pair.Resource.TypeName,
		"resource_id", pair.Resource.Identifier)

	// Build the specific chain for this resource type
	resourceChain := pair.ChainConstructor()

	// Only pass essential AWS parameters, not module-level parameters
	essentialArgs := p.extractEssentialArgs(pair.Args)
	if len(essentialArgs) > 0 {
		resourceChain.WithConfigs(cfg.WithArgs(essentialArgs))
	}

	// Process the resource
	if err := resourceChain.Send(pair.Resource); err != nil {
		slog.Error("Failed to send resource to chain", "error", err)
		return err
	}
	resourceChain.Close()

	// Stream outputs while the chain is running - consume before Wait()
	for output, ok := chain.RecvAs[jtypes.NPInput](resourceChain); ok; output, ok = chain.RecvAs[jtypes.NPInput](resourceChain) {
		slog.Debug("Forwarding output", "resource_type", pair.Resource.TypeName, "output_type", fmt.Sprintf("%T", output))
		if err := p.Send(output); err != nil {
			slog.Error("Failed to send output", "error", err)
			return err
		}
	}

	// Wait for chain completion after consuming all outputs
	resourceChain.Wait()

	if err := resourceChain.Error(); err != nil {
		slog.Error("Error processing resource chain", "resource", pair.Resource, "error", err)
		return err
	}

	slog.Debug("Completed processing resource chain", "resource_type", pair.Resource.TypeName)
	return nil
}

// extractEssentialArgs extracts only AWS-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AWSResourceChainProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential AWS parameters that resource chains need
	essentialParams := map[string]bool{
		"profile":          true, // AWS profile
		"profile-dir":      true, // AWS profile directory
		"regions":          true, // AWS regions
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from resource chain", "param", key)
		}
	}

	return essential
}
