package hierarchy

import (
	"context"
	"fmt"
	"log/slog"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	serviceusage "cloud.google.com/go/serviceusage/apiv1"
	serviceusagepb "cloud.google.com/go/serviceusage/apiv1/serviceusagepb"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type GcpAssetSearchOrgLink struct {
	*base.NativeGCPLink
	assetClient     *asset.Client
	resourceCounts  map[string]int
	assetAPIProject string
}

func NewGcpAssetSearchOrgLink(args map[string]any) *GcpAssetSearchOrgLink {
	return &GcpAssetSearchOrgLink{
		NativeGCPLink:  base.NewNativeGCPLink("gcp-asset-search-org", args),
		resourceCounts: make(map[string]int),
	}
}

func (g *GcpAssetSearchOrgLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to ADC project)"),
	)
	return params
}

func (g *GcpAssetSearchOrgLink) Initialize(ctx context.Context) error {
	g.assetAPIProject = g.ArgString("asset-api-project", "")
	if g.assetAPIProject == "" {
		adcProject, err := GetProjectFromADC(ctx)
		if err != nil {
			return fmt.Errorf("--asset-api-project not provided and could not determine project from ADC: %w", err)
		}
		g.assetAPIProject = adcProject
		slog.Debug("Using project from ADC for Asset API", "project", adcProject)
	}

	var err error
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions()...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchOrgLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Organization" {
		return nil, fmt.Errorf("expected organization resource, got %s", resource.ResourceType)
	}

	if err := CheckAssetAPIEnabled(g.assetAPIProject, g.ClientOptions()...); err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("organizations/%s", resource.ResourceID)
	return g.performAssetSearch(ctx, scope, "organization", resource)
}

func (g *GcpAssetSearchOrgLink) performAssetSearch(ctx context.Context, scope, scopeType string, resource output.CloudResource) ([]any, error) {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)
	req := &assetpb.SearchAllResourcesRequest{
		Scope: scope,
	}
	it := g.assetClient.SearchAllResources(ctx, req)
	totalCount := 0
	for {
		assetResource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate assets: %w", err)
		}
		assetType := assetResource.AssetType
		g.resourceCounts[assetType]++
		totalCount++
	}
	slog.Info("Asset search completed", "scope", scope, "totalResources", totalCount, "uniqueTypes", len(g.resourceCounts))

	var resources []*helpers.ResourceCount
	for assetType, count := range g.resourceCounts {
		resources = append(resources, &helpers.ResourceCount{
			ResourceType: assetType,
			Count:        count,
		})
	}
	envDetails := &helpers.GCPEnvironmentDetails{
		ScopeType: scopeType,
		ScopeName: resource.DisplayName,
		ScopeID:   resource.ResourceID,
		Location:  getLocation(resource),
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	return []any{envDetails}, nil
}

type GcpAssetSearchFolderLink struct {
	*base.NativeGCPLink
	assetClient     *asset.Client
	resourceCounts  map[string]int
	assetAPIProject string
}

func NewGcpAssetSearchFolderLink(args map[string]any) *GcpAssetSearchFolderLink {
	return &GcpAssetSearchFolderLink{
		NativeGCPLink:  base.NewNativeGCPLink("gcp-asset-search-folder", args),
		resourceCounts: make(map[string]int),
	}
}

func (g *GcpAssetSearchFolderLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to ADC project)"),
	)
	return params
}

func (g *GcpAssetSearchFolderLink) Initialize(ctx context.Context) error {
	g.assetAPIProject = g.ArgString("asset-api-project", "")
	if g.assetAPIProject == "" {
		adcProject, err := GetProjectFromADC(ctx)
		if err != nil {
			return fmt.Errorf("--asset-api-project not provided and could not determine project from ADC: %w", err)
		}
		g.assetAPIProject = adcProject
		slog.Debug("Using project from ADC for Asset API", "project", adcProject)
	}

	var err error
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions()...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchFolderLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Folder" {
		return nil, fmt.Errorf("expected folder resource, got %s", resource.ResourceType)
	}

	if err := CheckAssetAPIEnabled(g.assetAPIProject, g.ClientOptions()...); err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("folders/%s", resource.ResourceID)
	return g.performAssetSearch(ctx, scope, "folder", resource)
}

func (g *GcpAssetSearchFolderLink) performAssetSearch(ctx context.Context, scope, scopeType string, resource output.CloudResource) ([]any, error) {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)
	req := &assetpb.SearchAllResourcesRequest{
		Scope: scope,
	}
	it := g.assetClient.SearchAllResources(ctx, req)
	totalCount := 0
	for {
		assetResource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate assets: %w", err)
		}
		assetType := assetResource.AssetType
		g.resourceCounts[assetType]++
		totalCount++
	}
	slog.Info("Asset search completed", "scope", scope, "totalResources", totalCount, "uniqueTypes", len(g.resourceCounts))

	var resources []*helpers.ResourceCount
	for assetType, count := range g.resourceCounts {
		resources = append(resources, &helpers.ResourceCount{
			ResourceType: assetType,
			Count:        count,
		})
	}
	envDetails := &helpers.GCPEnvironmentDetails{
		ScopeType: scopeType,
		ScopeName: resource.DisplayName,
		ScopeID:   resource.ResourceID,
		Location:  getLocation(resource),
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	return []any{envDetails}, nil
}

type GcpAssetSearchProjectLink struct {
	*base.NativeGCPLink
	assetClient     *asset.Client
	resourceCounts  map[string]int
	assetAPIProject string
}

func NewGcpAssetSearchProjectLink(args map[string]any) *GcpAssetSearchProjectLink {
	return &GcpAssetSearchProjectLink{
		NativeGCPLink:  base.NewNativeGCPLink("gcp-asset-search-project", args),
		resourceCounts: make(map[string]int),
	}
}

func (g *GcpAssetSearchProjectLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to scoped project)"),
	)
	return params
}

func (g *GcpAssetSearchProjectLink) Initialize(ctx context.Context) error {
	g.assetAPIProject = g.ArgString("asset-api-project", "")

	var err error
	g.assetClient, err = asset.NewClient(ctx, g.ClientOptions()...)
	if err != nil {
		return fmt.Errorf("failed to create asset client: %w", err)
	}
	return nil
}

func (g *GcpAssetSearchProjectLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected output.CloudResource, got %T", input)
	}

	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Project" {
		return nil, fmt.Errorf("expected project resource, got %s", resource.ResourceType)
	}

	projectID := resource.ResourceID
	if g.assetAPIProject != "" {
		projectID = g.assetAPIProject
	}

	if err := CheckAssetAPIEnabled(projectID, g.ClientOptions()...); err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("projects/%s", resource.ResourceID)
	return g.performAssetSearch(ctx, scope, "project", resource)
}

func (g *GcpAssetSearchProjectLink) performAssetSearch(ctx context.Context, scope, scopeType string, resource output.CloudResource) ([]any, error) {
	slog.Info("Searching assets", "scope", scope, "scopeName", resource.DisplayName)

	req := &assetpb.SearchAllResourcesRequest{
		Scope: scope,
	}
	it := g.assetClient.SearchAllResources(ctx, req)
	totalCount := 0
	for {
		assetResource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate assets: %w", err)
		}
		assetType := assetResource.AssetType
		g.resourceCounts[assetType]++
		totalCount++
	}
	slog.Info("Asset search completed", "scope", scope, "totalResources", totalCount, "uniqueTypes", len(g.resourceCounts))

	var resources []*helpers.ResourceCount
	for assetType, count := range g.resourceCounts {
		resources = append(resources, &helpers.ResourceCount{
			ResourceType: assetType,
			Count:        count,
		})
	}
	envDetails := &helpers.GCPEnvironmentDetails{
		ScopeType: scopeType,
		ScopeName: resource.DisplayName,
		ScopeID:   resource.ResourceID,
		Location:  getLocation(resource),
		Labels:    getLabelsFromResource(resource),
		Resources: resources,
	}
	return []any{envDetails}, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func getLabelsFromResource(resource output.CloudResource) map[string]string {
	labels := make(map[string]string)
	if resource.Properties == nil {
		return labels
	}
	if labelsRaw, ok := resource.Properties["labels"]; ok {
		if labelMap, ok := labelsRaw.(map[string]string); ok {
			return labelMap
		}
	}
	return labels
}

func getLocation(resource output.CloudResource) string {
	if resource.Properties == nil {
		return ""
	}
	if location, ok := resource.Properties["location"].(string); ok {
		return location
	}
	return ""
}

func CheckAssetAPIEnabled(projectID string, clientOptions ...option.ClientOption) error {
	ctx := context.Background()
	client, err := serviceusage.NewClient(ctx, clientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create service usage client: %w", err)
	}
	defer client.Close()
	serviceName := fmt.Sprintf("projects/%s/services/cloudasset.googleapis.com", projectID)
	req := &serviceusagepb.GetServiceRequest{
		Name: serviceName,
	}
	resp, err := client.GetService(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to check Cloud Asset API status: %w. Enable it with: gcloud services enable cloudasset.googleapis.com --project=%s", err, projectID)
	}
	if resp.State != serviceusagepb.State_ENABLED {
		return fmt.Errorf("Cloud Asset API is not enabled for project %s. Enable it with: gcloud services enable cloudasset.googleapis.com --project=%s", projectID, projectID)
	}
	slog.Debug("Cloud Asset API is enabled", "project", projectID)
	return nil
}

func GetProjectFromADC(ctx context.Context) (string, error) {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to find default credentials: %w", err)
	}
	if creds.ProjectID == "" {
		return "", fmt.Errorf("no project ID found in application default credentials")
	}
	return creds.ProjectID, nil
}
