package aws

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AWSPublicResourcesProcessor processes ResourceChainPair objects concurrently for public resources
type AWSPublicResourcesProcessor struct {
	*base.AwsReconLink
}

func NewAWSPublicResourcesProcessor(configs ...cfg.Config) chain.Link {
	p := &AWSPublicResourcesProcessor{}
	p.AwsReconLink = base.NewAwsReconLink(p, configs...)
	return p
}

func (p *AWSPublicResourcesProcessor) Process(pair *ResourceChainPair) error {
	slog.Debug("Processing public resource chain",
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
	for output, ok := chain.RecvAs[*types.EnrichedResourceDescription](resourceChain); ok; output, ok = chain.RecvAs[*types.EnrichedResourceDescription](resourceChain) {
		slog.Debug("Forwarding output", "resource_type", pair.Resource.TypeName, "output_type", fmt.Sprintf("%T", output))
		if err := p.Send(output); err != nil {
			slog.Error("Failed to send output", "error", err)
			return err
		}
	}

	// Wait for chain completion after consuming all outputs
	resourceChain.Wait()

	if err := resourceChain.Error(); err != nil {
		slog.Error("Error processing public resource chain", "resource", pair.Resource, "error", err)
		return err
	}

	slog.Debug("Completed processing public resource chain", "resource_type", pair.Resource.TypeName)
	return nil
}

// extractEssentialArgs extracts only AWS-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AWSPublicResourcesProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential AWS parameters that resource chains need
	essentialParams := map[string]bool{
		"profile":          true, // AWS profile
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
			slog.Debug("Excluding non-essential parameter from public resource chain", "param", key)
		}
	}

	return essential
}