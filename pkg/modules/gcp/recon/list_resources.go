package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/compute"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/containers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/storage"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("gcp", "recon", GcpListResources.Metadata().Properties()["id"].(string), *GcpListResources)
}

var GcpListResources = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Resources",
		"List GCP resources across organization, folder, or project scope with optional resource type filtering.",
	).WithProperties(map[string]any{
		"id":          "list-resources",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}),
).WithLinks(
	NewGcpResourceListRouter,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	options.GcpProject(),
	options.GcpOrg(),
	options.GcpFolder(),
	options.GcpResourceTypes(),
	options.GcpIncludeSysProjects(),
).WithConfigs(
	cfg.WithArg("module-name", "list-resources"),
).WithAutoRun()

type GcpResourceListRouter struct {
	*chain.Base
	resourceTypes []string
	scope         *common.ScopeConfig
}

func NewGcpResourceListRouter(configs ...cfg.Config) chain.Link {
	r := &GcpResourceListRouter{}
	r.Base = chain.NewBase(r, configs...)
	r.SetParams(
		options.GcpProject(),
		options.GcpOrg(),
		options.GcpFolder(),
		options.GcpResourceTypes(),
		options.GcpIncludeSysProjects(),
	)
	return r
}

func (r *GcpResourceListRouter) Initialize() error {
	if err := r.Base.Initialize(); err != nil {
		return err
	}
	resourceTypes, err := cfg.As[[]string](r.Arg("type"))
	if err != nil {
		return fmt.Errorf("failed to get resource types: %w", err)
	}
	r.resourceTypes = resourceTypes
	if err := common.ValidateResourceTypes(r.resourceTypes, common.ResrouceIdentifier); err != nil {
		return err
	}
	scope, err := common.ParseScopeArgs(r.Args())
	if err != nil {
		return err
	}
	r.scope = scope
	return nil
}

func (r *GcpResourceListRouter) shouldSendResource(resourceType tab.CloudResourceType) bool {
	if len(r.resourceTypes) == 0 || r.resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range r.resourceTypes {
		if rt == resourceType.String() {
			return true
		}
		if common.ResrouceIdentifier(rt) == resourceType {
			return true
		}
	}
	return false
}

func (r *GcpResourceListRouter) shouldFanOutToResources() bool {
	if len(r.resourceTypes) == 0 || r.resourceTypes[0] == "all" {
		return true
	}
	for _, rt := range r.resourceTypes {
		resType := common.ResrouceIdentifier(rt)
		if resType != tab.GCPResourceOrganization &&
			resType != tab.GCPResourceFolder &&
			resType != tab.GCPResourceProject {
			return true
		}
	}
	return false
}

func (r *GcpResourceListRouter) Process(input string) error {
	switch r.scope.Type {
	case "org":
		return r.processOrganization()
	case "folder":
		return r.processFolder()
	case "project":
		return r.processProject()
	default:
		return fmt.Errorf("invalid scope type: %s", r.scope.Type)
	}
}

func (r *GcpResourceListRouter) processOrganization() error {
	orgChain := chain.NewChain(hierarchy.NewGcpOrgInfoLink())
	orgChain.WithConfigs(cfg.WithArgs(r.Args()))
	orgChain.Send(r.scope.Value)
	orgChain.Close()
	var orgResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](orgChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](orgChain) {
		orgResource = result
		if r.shouldSendResource(tab.GCPResourceOrganization) {
			r.Send(orgResource)
		}
	}
	if err := orgChain.Error(); err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}
	if orgResource == nil {
		return fmt.Errorf("organization not found: %s", r.scope.Value)
	}

	if r.shouldSendResource(tab.GCPResourceFolder) {
		folderChain := chain.NewChain(hierarchy.NewGcpOrgFolderListLink())
		folderChain.WithConfigs(cfg.WithArgs(r.Args()))
		folderChain.Send(*orgResource)
		folderChain.Close()
		for folder, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; folder, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
			r.Send(folder)
		}
		if err := folderChain.Error(); err != nil {
			return fmt.Errorf("failed to list folders in organization: %w", err)
		}
	}

	projectChain := chain.NewChain(hierarchy.NewGcpOrgProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*orgResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(project)
		}
		if r.shouldFanOutToResources() {
			r.fanOutToResources(*project)
		}
	}
	return projectChain.Error()
}

func (r *GcpResourceListRouter) processFolder() error {
	folderChain := chain.NewChain(hierarchy.NewGcpFolderInfoLink())
	folderChain.WithConfigs(cfg.WithArgs(r.Args()))
	folderChain.Send(r.scope.Value)
	folderChain.Close()
	var folderResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](folderChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](folderChain) {
		folderResource = result
		if r.shouldSendResource(tab.GCPResourceFolder) {
			r.Send(folderResource)
		}
	}
	if err := folderChain.Error(); err != nil {
		return fmt.Errorf("failed to get folder info: %w", err)
	}
	if folderResource == nil {
		return fmt.Errorf("folder not found: %s", r.scope.Value)
	}

	if r.shouldSendResource(tab.GCPResourceFolder) {
		subfolderChain := chain.NewChain(hierarchy.NewGcpFolderSubFolderListLink())
		subfolderChain.WithConfigs(cfg.WithArgs(r.Args()))
		subfolderChain.Send(*folderResource)
		subfolderChain.Close()
		for subfolder, ok := chain.RecvAs[*tab.GCPResource](subfolderChain); ok; subfolder, ok = chain.RecvAs[*tab.GCPResource](subfolderChain) {
			r.Send(subfolder)
		}
		if err := subfolderChain.Error(); err != nil {
			return fmt.Errorf("failed to list subfolders in folder: %w", err)
		}
	}

	projectChain := chain.NewChain(hierarchy.NewGcpFolderProjectListLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(*folderResource)
	projectChain.Close()
	for project, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; project, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(project)
		}
		if r.shouldFanOutToResources() {
			r.fanOutToResources(*project)
		}
	}
	return projectChain.Error()
}

func (r *GcpResourceListRouter) processProject() error {
	projectChain := chain.NewChain(hierarchy.NewGcpProjectInfoLink())
	projectChain.WithConfigs(cfg.WithArgs(r.Args()))
	projectChain.Send(r.scope.Value)
	projectChain.Close()
	var projectResource *tab.GCPResource
	for result, ok := chain.RecvAs[*tab.GCPResource](projectChain); ok; result, ok = chain.RecvAs[*tab.GCPResource](projectChain) {
		projectResource = result
		if r.shouldSendResource(tab.GCPResourceProject) {
			r.Send(projectResource)
		}
	}
	if err := projectChain.Error(); err != nil {
		return fmt.Errorf("failed to get project info: %w", err)
	}
	if projectResource == nil {
		return fmt.Errorf("project not found: %s", r.scope.Value)
	}
	if r.shouldFanOutToResources() {
		return r.fanOutToResources(*projectResource)
	}
	return nil
}

func (r *GcpResourceListRouter) fanOutToResources(project tab.GCPResource) error {
	if project.ResourceType != tab.GCPResourceProject {
		return fmt.Errorf("expected project resource, got %s", project.ResourceType)
	}
	chains := buildResourceChains(r.resourceTypes)
	if len(chains) == 0 {
		slog.Debug("No resource types to scan", "project", project.Name)
		return nil
	}
	multi := chain.NewMulti(chains...)
	multi.WithConfigs(cfg.WithArgs(r.Args()))
	multi.WithStrictness(chain.Lax)
	multi.Send(project)
	multi.Close()
	for result, ok := chain.RecvAs[*tab.GCPResource](multi); ok; result, ok = chain.RecvAs[*tab.GCPResource](multi) {
		r.Send(result)
	}
	if err := multi.Error(); err != nil {
		slog.Warn("Some resources failed for project (continuing with others)", "project", project.Name, "error", err)
		resourceErrors := common.ParseAggregatedListError(project.Name, err.Error())
		for _, resourceError := range resourceErrors {
			r.Send(resourceError)
		}
	}
	return nil
}

func buildResourceChains(resourceTypes []string) []chain.Link {
	var chains []chain.Link
	includeAll := len(resourceTypes) == 0 || resourceTypes[0] == "all"
	shouldInclude := func(resourceType string) bool {
		if includeAll {
			return true
		}
		for _, rt := range resourceTypes {
			if rt == resourceType {
				return true
			}
			if common.ResrouceIdentifier(rt) == common.ResrouceIdentifier(resourceType) {
				return true
			}
		}
		return false
	}

	if shouldInclude("bucket") {
		chains = append(chains, chain.NewChain(storage.NewGcpStorageBucketListLink()))
	}
	if shouldInclude("sql") {
		chains = append(chains, chain.NewChain(storage.NewGcpSQLInstanceListLink()))
	}

	if shouldInclude("instance") || shouldInclude("vm") {
		chains = append(chains, chain.NewChain(compute.NewGcpInstanceListLink()))
	}

	if shouldInclude("forwardingrule") || shouldInclude("globalforwardingrule") ||
		shouldInclude("address") || shouldInclude("dnszone") || shouldInclude("managedzone") {
		chains = append(chains, chain.NewChain(compute.NewGCPNetworkingFanOut()))
	}

	if shouldInclude("function") || shouldInclude("functionv2") || shouldInclude("functionv1") || shouldInclude("cloudfunction") {
		chains = append(chains, chain.NewChain(applications.NewGcpFunctionListLink()))
	}
	if shouldInclude("runservice") || shouldInclude("cloudrunservice") {
		chains = append(chains, chain.NewChain(applications.NewGcpCloudRunServiceListLink()))
	}
	if shouldInclude("appengineservice") {
		chains = append(chains, chain.NewChain(applications.NewGcpAppEngineApplicationListLink()))
	}

	if shouldInclude("artifactrepo") || shouldInclude("containerimage") ||
		shouldInclude("dockerimage") || shouldInclude("artifactoryimage") {
		chains = append(chains, chain.NewChain(
			containers.NewGcpRepositoryListLink(),
			containers.NewGcpContainerImageListLink(),
		))
	}

	return chains
}
