package applications

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/types"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/option"
)

// FILE INFO:
// GcpAppEngineApplicationInfoLink - get info of a single App Engine application/service/version, Process(applicationName string); needs project and service and version
// GcpAppEngineApplicationListLink - list all App Engine applications/services/versions in a project, Process(resource tab.GCPResource)
// GcpAppEngineSecretsLink - extract secrets from an App Engine application/service/version, Process(input tab.GCPResource)

type GcpAppEngineApplicationInfoLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
	ProjectId        string
	ServiceId        string
	VersionId        string
}

// creates a link to get info of a single App Engine application/service/version
func NewGcpAppEngineApplicationInfoLink(projectId, serviceId, versionId string, clientOpts ...option.ClientOption) *GcpAppEngineApplicationInfoLink {
	link := &GcpAppEngineApplicationInfoLink{
		GcpBaseLink: base.NewGcpBaseLink("GcpAppEngineApplicationInfoLink", nil),
		ProjectId:   projectId,
		ServiceId:   serviceId,
		VersionId:   versionId,
	}
	link.ClientOptions = clientOpts
	return link
}

func (g *GcpAppEngineApplicationInfoLink) Initialize(ctx context.Context) error {
	if err := g.GcpBaseLink.Initialize(ctx); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	return nil
}

func (g *GcpAppEngineApplicationInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	_, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	app, err := g.appengineService.Apps.Get(g.ProjectId).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get App Engine application %s: %w", g.ProjectId, err)
	}
	service, err := g.appengineService.Apps.Services.Get(g.ProjectId, g.ServiceId).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get App Engine service %s: %w", g.ServiceId, err)
	}
	version, err := g.appengineService.Apps.Services.Versions.Get(g.ProjectId, g.ServiceId, g.VersionId).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get App Engine version %s: %w", g.VersionId, err)
	}
	gcpAppEngineVersion, err := tab.NewGCPResource(
		fmt.Sprintf("%s-%s", service.Id, version.Id), // resource name
		g.ProjectId,                         // accountRef (project ID)
		tab.GCPResourceAppEngineApplication, // resource type
		linkPostProcessAppEngineApplication(app, service, version), // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP App Engine version resource: %w", err)
	}
	gcpAppEngineVersion.DisplayName = gcpAppEngineVersion.Name
	return []any{gcpAppEngineVersion}, nil
}

type GcpAppEngineApplicationListLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
}

// creates a link to list all App Engine applications/services/versions in a project
func NewGcpAppEngineApplicationListLink(clientOpts ...option.ClientOption) *GcpAppEngineApplicationListLink {
	link := &GcpAppEngineApplicationListLink{
		GcpBaseLink: base.NewGcpBaseLink("GcpAppEngineApplicationListLink", nil),
	}
	link.ClientOptions = clientOpts
	return link
}

func (g *GcpAppEngineApplicationListLink) Initialize(ctx context.Context) error {
	if err := g.GcpBaseLink.Initialize(ctx); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	return nil
}

func (g *GcpAppEngineApplicationListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}
	projectId := resource.Name
	app, err := g.appengineService.Apps.Get(projectId).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get App Engine application")
	}
	servicesCall := g.appengineService.Apps.Services.List(projectId)
	servicesResp, err := servicesCall.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list App Engine services in project")
	}

	var results []any
	for _, service := range servicesResp.Services {
		versionsCall := g.appengineService.Apps.Services.Versions.List(projectId, service.Id)
		versionsResp, err := versionsCall.Do()
		if err != nil {
			slog.Error("Failed to list versions for App Engine service", "error", err, "service", service.Id)
			continue
		}
		for _, version := range versionsResp.Versions {
			gcpAppEngineVersion, err := tab.NewGCPResource(
				fmt.Sprintf("%s-%s", service.Id, version.Id), // resource name
				projectId,                           // accountRef (project ID)
				tab.GCPResourceAppEngineApplication, // resource type
				linkPostProcessAppEngineApplication(app, service, version), // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP App Engine version resource", "error", err, "service", service.Id, "version", version.Id)
				continue
			}
			gcpAppEngineVersion.DisplayName = gcpAppEngineVersion.Name
			results = append(results, gcpAppEngineVersion)
		}
	}
	return results, nil
}

type GcpAppEngineSecretsLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
}

// creates a link to scan App Engine application/service/version for secrets
func NewGcpAppEngineSecretsLink(clientOpts ...option.ClientOption) *GcpAppEngineSecretsLink {
	link := &GcpAppEngineSecretsLink{
		GcpBaseLink: base.NewGcpBaseLink("GcpAppEngineSecretsLink", nil),
	}
	link.ClientOptions = clientOpts
	return link
}

func (g *GcpAppEngineSecretsLink) Initialize(ctx context.Context) error {
	if err := g.GcpBaseLink.Initialize(ctx); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(ctx, g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	return nil
}

func (g *GcpAppEngineSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceAppEngineApplication {
		return nil, nil
	}
	projectId := resource.AccountRef
	serviceId, _ := resource.Properties["serviceId"].(string)
	versionId, _ := resource.Properties["versionId"].(string)
	if projectId == "" || serviceId == "" || versionId == "" {
		return nil, nil
	}
	ver, err := g.appengineService.Apps.Services.Versions.Get(projectId, serviceId, versionId).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get app engine version for secrets extraction")
	}

	var results []any
	if len(ver.EnvVariables) > 0 {
		if content, err := json.Marshal(ver.EnvVariables); err == nil {
			results = append(results, types.NpInput{
				Content: string(content),
				Provenance: types.NpProvenance{
					Platform:     "gcp",
					ResourceType: fmt.Sprintf("%s::EnvVariables", tab.GCPResourceAppEngineApplication.String()),
					ResourceID:   fmt.Sprintf("projects/%s/services/%s/versions/%s", projectId, serviceId, versionId),
					Region:       resource.Region,
					AccountID:    projectId,
				},
			})
		}
	}
	return results, nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessAppEngineApplication(app *appengine.Application, service *appengine.Service, version *appengine.Version) map[string]any {
	properties := map[string]any{
		"applicationId": app.Id,
		"locationId":    app.LocationId,
		"serviceId":     service.Id,
		"serviceName":   service.Name,
		"versionId":     version.Id,
		"versionName":   version.Name,
		"servingStatus": version.ServingStatus,
		"runtime":       version.Runtime,
	}
	// properties["handlers"] = version.Handlers
	properties["envVariables"] = version.EnvVariables
	if app.DefaultHostname != "" {
		var publicURL string
		if service.Id == "default" {
			publicURL = fmt.Sprintf("https://%s-dot-%s", version.Id, app.DefaultHostname)
		} else {
			publicURL = fmt.Sprintf("https://%s-dot-%s-dot-%s", version.Id, service.Id, app.DefaultHostname)
		}
		properties["publicURL"] = publicURL
	}
	if app.DispatchRules != nil {
		var customDomains []string
		for _, rule := range app.DispatchRules {
			if rule.Domain != "" && !strings.Contains(rule.Domain, app.DefaultHostname) {
				customDomains = append(customDomains, rule.Domain)
			}
		}
		if len(customDomains) > 0 {
			properties["publicDomains"] = customDomains
		}
	}
	return properties
}
