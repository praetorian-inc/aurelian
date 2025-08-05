package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "analyze", AWSIPLookup.Metadata().Properties()["id"].(string), *AWSIPLookup)
}

var AWSIPLookup = chain.NewModule(
	cfg.NewMetadata(
		"AWS IP Lookup",
		"Search AWS IP ranges for a specific IP address",
	).WithProperties(map[string]any{
		"id":          "ip-lookup",
		"platform":    "aws",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://ip-ranges.amazonaws.com/ip-ranges.json",
		},
	}).WithChainInputParam(
		options.IP().Name(),
	),
).WithLinks(
	aws.NewIPLookup,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.IP(),
)
