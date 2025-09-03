package azure

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureResourceChainProcessor processes AzureResourceChainPair objects concurrently
type AzureResourceChainProcessor struct {
	*chain.Base
}

type AzureResourceChainPair struct {
	Resource         *model.AzureResource
	ChainConstructor func() chain.Chain
	Args             map[string]any
}

func NewAzureResourceChainProcessor(configs ...cfg.Config) chain.Link {
	p := &AzureResourceChainProcessor{}
	p.Base = chain.NewBase(p, configs...)
	return p
}

func (p *AzureResourceChainProcessor) Process(pair *AzureResourceChainPair) error {
	slog.Debug("Processing Azure resource chain",
		"resource_type", string(pair.Resource.ResourceType),
		"resource_id", pair.Resource.Name)

	// Build the specific chain for this resource type
	resourceChain := pair.ChainConstructor()

	// Only pass essential Azure parameters, not module-level parameters
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
		slog.Debug("Forwarding output", "resource_type", string(pair.Resource.ResourceType), "output_type", fmt.Sprintf("%T", output))
		if err := p.Send(output); err != nil {
			slog.Error("Failed to send output", "error", err)
			return err
		}
	}

	// Wait for chain completion after consuming all outputs
	resourceChain.Wait()

	if err := resourceChain.Error(); err != nil {
		slog.Error("Error processing Azure resource chain", "resource", pair.Resource, "error", err)
		return err
	}

	slog.Debug("Completed processing Azure resource chain", "resource_type", string(pair.Resource.ResourceType))
	return nil
}

// extractEssentialArgs extracts only Azure-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AzureResourceChainProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential Azure parameters that resource chains need
	essentialParams := map[string]bool{
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
		"worker-count":     true, // Worker count for Azure operations
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from Azure resource chain", "param", key)
		}
	}

	return essential
}