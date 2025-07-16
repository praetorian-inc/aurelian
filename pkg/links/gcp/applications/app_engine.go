package applications

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/appengine/v1"
)

// FILE INFO:
// GcpAppEngineApplicationInfoLink
// GcpAppEngineApplicationListLink

// get information about a specific App Engine application/service/version
type GcpAppEngineApplicationInfoLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
	ProjectId        string
	ServiceId        string
	VersionId        string
}

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
	// Get the App Engine application
	app, err := g.appengineService.Apps.Get(g.ProjectId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine application %s: %w", g.ProjectId, err)
	}

	// Get the specific service
	service, err := g.appengineService.Apps.Services.Get(g.ProjectId, g.ServiceId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine service %s: %w", g.ServiceId, err)
	}

	// Get the specific version
	version, err := g.appengineService.Apps.Services.Versions.Get(g.ProjectId, g.ServiceId, g.VersionId).Do()
	if err != nil {
		return fmt.Errorf("failed to get App Engine version %s: %w", g.VersionId, err)
	}

	properties := linkPostProcessAppEngineApplication(app, service, version, true)
	gcpAppEngineVersion, err := tab.NewGCPResource(
		fmt.Sprintf("%s-%s", service.Id, version.Id), // resource name
		g.ProjectId,                         // accountRef (project ID)
		tab.GCPResourceAppEngineApplication, // resource type
		properties,                          // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP App Engine version resource: %w", err)
	}
	g.Send(gcpAppEngineVersion)
	return nil
}

// linkPostProcessAppEngineApplication consolidates App Engine application processing logic for both info and list links
// detailedInfo controls whether to include detailed deployment and configuration information
func linkPostProcessAppEngineApplication(app *appengine.Application, service *appengine.Service, version *appengine.Version, detailedInfo bool) map[string]any {
	properties := map[string]any{
		"applicationId":  app.Id,
		"locationId":     app.LocationId,
		"serviceId":      service.Id,
		"serviceName":    service.Name,
		"versionId":      version.Id,
		"versionName":    version.Name,
		"servingStatus":  version.ServingStatus,
		"runtime":        version.Runtime,
		"env":            version.Env,
		"creationTime":   version.CreateTime,
		"diskUsageBytes": version.DiskUsageBytes,
		"instanceClass":  version.InstanceClass,
		"threadsafe":     version.Threadsafe,
	}

	// Include detailed deployment information only for info links
	if detailedInfo {
		properties["automaticScaling"] = version.AutomaticScaling
		properties["basicScaling"] = version.BasicScaling
		properties["manualScaling"] = version.ManualScaling
		properties["network"] = version.Network
		properties["resources"] = version.Resources
		properties["handlers"] = version.Handlers
		properties["errorHandlers"] = version.ErrorHandlers
		properties["libraries"] = version.Libraries
		properties["envVariables"] = version.EnvVariables
		properties["defaultExpiration"] = version.DefaultExpiration
		properties["healthCheck"] = version.HealthCheck
	}

	// Extract public URL (common logic)
	if app.DefaultHostname != "" {
		var publicURL string
		if service.Id == "default" {
			// Default service uses the main hostname with version
			publicURL = fmt.Sprintf("https://%s-dot-%s", version.Id, app.DefaultHostname)
		} else {
			// Non-default services
			publicURL = fmt.Sprintf("https://%s-dot-%s-dot-%s", version.Id, service.Id, app.DefaultHostname)
		}
		properties["publicURL"] = publicURL
	}

	// Extract custom domains if available (common logic)
	if app.DispatchRules != nil {
		var customDomains []string
		for _, rule := range app.DispatchRules {
			if rule.Domain != "" && !strings.Contains(rule.Domain, app.DefaultHostname) {
				customDomains = append(customDomains, rule.Domain)
			}
		}
		if len(customDomains) > 0 {
			properties["customDomains"] = customDomains
		}
	}

	return properties
}

// list App Engine applications within a project
type GcpAppEngineApplicationListLink struct {
	*base.GcpBaseLink
	appengineService *appengine.APIService
}

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

	// Get the App Engine application for this project
	app, err := g.appengineService.Apps.Get(projectId).Do()
	if err != nil {
		// App Engine might not be enabled for this project
		slog.Debug("Failed to get App Engine application, likely not enabled", "project", projectId, "error", err)
		return nil
	}

	// List services within the application
	servicesCall := g.appengineService.Apps.Services.List(projectId)
	servicesResp, err := servicesCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list App Engine services in project %s: %w", projectId, err)
	}

	for _, service := range servicesResp.Services {
		// List versions for each service
		versionsCall := g.appengineService.Apps.Services.Versions.List(projectId, service.Id)
		versionsResp, err := versionsCall.Do()
		if err != nil {
			slog.Error("Failed to list versions for App Engine service", "error", err, "service", service.Id)
			continue
		}

		for _, version := range versionsResp.Versions {
			properties := linkPostProcessAppEngineApplication(app, service, version, false)
			gcpAppEngineVersion, err := tab.NewGCPResource(
				fmt.Sprintf("%s-%s", service.Id, version.Id), // resource name
				projectId,                           // accountRef (project ID)
				tab.GCPResourceAppEngineApplication, // resource type
				properties,                          // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP App Engine version resource", "error", err, "service", service.Id, "version", version.Id)
				continue
			}
			g.Send(gcpAppEngineVersion)
		}
	}
	return nil
}
