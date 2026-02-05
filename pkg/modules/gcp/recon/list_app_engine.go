package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListAppEngineModule{})
}

// GCPListAppEngineModule lists all App Engine applications in a GCP project
type GCPListAppEngineModule struct{}

func (m *GCPListAppEngineModule) ID() string {
	return "app-engine-list"
}

func (m *GCPListAppEngineModule) Name() string {
	return "GCP List App Engine"
}

func (m *GCPListAppEngineModule) Description() string {
	return "List all App Engine applications in a GCP project."
}

func (m *GCPListAppEngineModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListAppEngineModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListAppEngineModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListAppEngineModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListAppEngineModule) References() []string {
	return []string{}
}

func (m *GCPListAppEngineModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "creds-file",
			Description: "Path to GCP service account credentials JSON file",
			Type:        "string",
		},
	}
}

func (m *GCPListAppEngineModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional parameters
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	} else {
		// Attempt to use application default credentials
		_, err := google.FindDefaultCredentials(cfg.Context)
		if err != nil {
			return nil, fmt.Errorf("cannot find default credentials (use --creds-file): %w", err)
		}
	}

	// Create resource manager service to get project info
	resourceManagerService, err := cloudresourcemanager.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	// Get project info
	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	// Create appengine service
	appengineService, err := appengine.NewService(context.Background(), clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create appengine service: %w", err)
	}

	// Get App Engine application
	app, err := appengineService.Apps.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get App Engine application %s: %w", projectID, err)
	}

	// List all services
	servicesCall := appengineService.Apps.Services.List(projectID)
	servicesResp, err := servicesCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list App Engine services in project %s: %w", projectID, err)
	}

	var results []plugin.Result

	// Iterate through services and versions
	for _, service := range servicesResp.Services {
		versionsCall := appengineService.Apps.Services.Versions.List(projectID, service.Id)
		versionsResp, err := versionsCall.Do()
		if err != nil {
			slog.Error("Failed to list versions for App Engine service", "error", err, "service", service.Id)
			continue
		}

		for _, version := range versionsResp.Versions {
			// Build properties
			properties := map[string]any{
				"applicationId": app.Id,
				"locationId":    app.LocationId,
				"serviceId":     service.Id,
				"serviceName":   service.Name,
				"versionId":     version.Id,
				"versionName":   version.Name,
				"servingStatus": version.ServingStatus,
				"runtime":       version.Runtime,
				"envVariables":  version.EnvVariables,
			}

			// Add public URL if hostname is available
			if app.DefaultHostname != "" {
				var publicURL string
				if service.Id == "default" {
					publicURL = fmt.Sprintf("https://%s-dot-%s", version.Id, app.DefaultHostname)
				} else {
					publicURL = fmt.Sprintf("https://%s-dot-%s-dot-%s", version.Id, service.Id, app.DefaultHostname)
				}
				properties["publicURL"] = publicURL
			}

			// Add custom domains if available
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

			// Create cloud resource
			gcpAppEngineVersion := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "appengine.googleapis.com/Application",
				ResourceID:   fmt.Sprintf("projects/%s/services/%s/versions/%s", projectID, service.Id, version.Id),
				AccountRef:   projectID,
				DisplayName:  fmt.Sprintf("%s-%s", service.Id, version.Id),
				Properties:   properties,
			}

			results = append(results, plugin.Result{
				Data: gcpAppEngineVersion,
				Metadata: map[string]any{
					"module":      "app-engine-list",
					"platform":    "gcp",
					"type":        "appengine-version",
					"project":     projectID,
					"projectName": project.Name,
				},
			})
		}
	}

	return results, nil
}
