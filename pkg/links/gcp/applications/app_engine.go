package applications

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/appengine/v1"
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
func NewGcpAppEngineApplicationInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpAppEngineApplicationInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAppEngineApplicationInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		cfg.NewParam[string]("service", "App Engine service ID").WithDefault("default").AsRequired(),
		cfg.NewParam[string]("version", "App Engine version ID").AsRequired(),
	)
	return params
}

func (g *GcpAppEngineApplicationInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	serviceId, err := cfg.As[string](g.Arg("service"))
	if err != nil {
		return fmt.Errorf("failed to get service: %w", err)
	}
	g.ServiceId = serviceId
	versionId, err := cfg.As[string](g.Arg("version"))
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}
	g.VersionId = versionId
	return nil
}

func (g *GcpAppEngineApplicationInfoLink) Process(applicationName string) error {
	app, err := g.appengineService.Apps.Get(g.ProjectId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine application %s: %w", g.ProjectId, err)
	}
	service, err := g.appengineService.Apps.Services.Get(g.ProjectId, g.ServiceId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine service %s: %w", g.ServiceId, err)
	}
	version, err := g.appengineService.Apps.Services.Versions.Get(g.ProjectId, g.ServiceId, g.VersionId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine version %s: %w", g.VersionId, err)
	}
	gcpAppEngineVersion, err := tab.NewGCPResource(
		fmt.Sprintf("%s-%s", service.Id, version.Id), // resource name
		g.ProjectId,                         // accountRef (project ID)
		tab.GCPResourceAppEngineApplication, // resource type
		linkPostProcessAppEngineApplication(app, service, version), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP App Engine version resource: %w", err)
	}
	gcpAppEngineVersion.DisplayName = gcpAppEngineVersion.Name
	g.Send(gcpAppEngineVersion)
	return nil
}

type GcpAppEngineApplicationListLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
}

// creates a link to list all App Engine applications/services/versions in a project
func NewGcpAppEngineApplicationListLink(configs ...cfg.Config) chain.Link {
	g := &GcpAppEngineApplicationListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAppEngineApplicationListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	return nil
}

func (g *GcpAppEngineApplicationListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	app, err := g.appengineService.Apps.Get(projectId).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get App Engine application")
	}
	servicesCall := g.appengineService.Apps.Services.List(projectId)
	servicesResp, err := servicesCall.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list App Engine services in project")
	}
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
			g.Send(gcpAppEngineVersion)
		}
	}
	return nil
}

type GcpAppEngineSecretsLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
}

// creates a link to scan App Engine application/service/version for secrets
func NewGcpAppEngineSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpAppEngineSecretsLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpAppEngineSecretsLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.appengineService, err = appengine.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create appengine service: %w", err)
	}
	return nil
}

func (g *GcpAppEngineSecretsLink) Process(input tab.GCPResource) error {
	if input.ResourceType != tab.GCPResourceAppEngineApplication {
		return nil
	}
	projectId := input.AccountRef
	serviceId, _ := input.Properties["serviceId"].(string)
	versionId, _ := input.Properties["versionId"].(string)
	if projectId == "" || serviceId == "" || versionId == "" {
		return nil
	}
	ver, err := g.appengineService.Apps.Services.Versions.Get(projectId, serviceId, versionId).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get app engine version for secrets extraction")
	}
	if len(ver.EnvVariables) > 0 {
		if content, err := json.Marshal(ver.EnvVariables); err == nil {
			g.Send(jtypes.NPInput{
				Content: string(content),
				Provenance: jtypes.NPProvenance{
					Platform:     "gcp",
					ResourceType: fmt.Sprintf("%s::EnvVariables", tab.GCPResourceAppEngineApplication.String()),
					ResourceID:   fmt.Sprintf("projects/%s/services/%s/versions/%s", projectId, serviceId, versionId),
					Region:       input.Region,
					AccountID:    projectId,
				},
			})
		}
	}
	return nil
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
