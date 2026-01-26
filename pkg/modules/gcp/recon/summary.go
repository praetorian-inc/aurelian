package recon

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("gcp", "recon", GcpSummary.Metadata().Properties()["id"].(string), *GcpSummary)
}

var GcpSummary = chain.NewModule(
	cfg.NewMetadata(
		"GCP Summary",
		"Summarize resources within an organization, folder, or project scope (requires Asset API)",
	).WithProperties(map[string]any{
		"id":          "summary",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://cloud.google.com/asset-inventory/docs/overview",
			"https://cloud.google.com/asset-inventory/docs/search-resources",
		},
	}),
).WithLinks(
	NewGcpSummaryRouter,
	hierarchy.NewGcpSummaryOutputFormatterLink,
).WithOutputters(
	outputters.NewMarkdownTableConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
	options.GcpAssetAPIProject(),
).WithConfigs(
	cfg.WithArg("module-name", "summary"),
).WithAutoRun()

type GcpSummaryRouter struct {
	*chain.Base
	scope *common.ScopeConfig
}

func NewGcpSummaryRouter(configs ...cfg.Config) chain.Link {
	r := &GcpSummaryRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
		options.GcpAssetAPIProject(),
	)
	return r
}

func (r *GcpSummaryRouter) Initialize() error {
	if err := r.Base.Initialize(); err != nil {
		return err
	}
	scope, err := common.ParseScopeArgs(r.Args())
	if err != nil {
		return err
	}
	r.scope = scope
	return nil
}

func (r *GcpSummaryRouter) Process(input string) error {
	infoChain, assetSearchLink := r.buildChainForScope()
	infoChain.WithConfigs(cfg.WithArgs(r.Args()))
	infoChain.Send(r.scope.Value)
	infoChain.Close()

	var scopeResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](infoChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](infoChain) {
		scopeResource = result
	}
	if err := infoChain.Error(); err != nil {
		return fmt.Errorf("failed to get %s info: %w", r.scope.Type, err)
	}
	if scopeResource == nil {
		return fmt.Errorf("%s not found: %s", r.scope.Type, r.scope.Value)
	}

	assetSearchChain := chain.NewChain(assetSearchLink)
	assetSearchChain.WithConfigs(cfg.WithArgs(r.Args()))
	assetSearchChain.Send(*scopeResource)
	assetSearchChain.Close()
	for envDetails, ok := chain.RecvAs[any](assetSearchChain); ok; envDetails, ok = chain.RecvAs[any](assetSearchChain) {
		r.Send(envDetails)
	}
	return assetSearchChain.Error()
}

func (r *GcpSummaryRouter) buildChainForScope() (chain.Chain, chain.Link) {
	switch r.scope.Type {
	case "org":
		return chain.NewChain(hierarchy.NewGcpOrgInfoLink()), hierarchy.NewGcpAssetSearchOrgLink()
	case "folder":
		return chain.NewChain(hierarchy.NewGcpFolderInfoLink()), hierarchy.NewGcpAssetSearchFolderLink()
	case "project":
		return chain.NewChain(hierarchy.NewGcpProjectInfoLink()), hierarchy.NewGcpAssetSearchProjectLink()
	default:
		return nil, nil
	}
}
