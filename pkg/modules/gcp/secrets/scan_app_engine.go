package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPScanAppEngineModule{})
}

// GCPScanAppEngineModule scans App Engine applications for secrets
type GCPScanAppEngineModule struct{}

func (m *GCPScanAppEngineModule) ID() string {
	return "app-engine-secrets"
}

func (m *GCPScanAppEngineModule) Name() string {
	return "GCP Scan App Engine Secrets"
}

func (m *GCPScanAppEngineModule) Description() string {
	return "List all App Engine applications in a GCP project and scan them for secrets."
}

func (m *GCPScanAppEngineModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPScanAppEngineModule) Category() plugin.Category {
	return plugin.CategorySecrets
}

func (m *GCPScanAppEngineModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPScanAppEngineModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPScanAppEngineModule) References() []string {
	return []string{}
}

func (m *GCPScanAppEngineModule) Parameters() []plugin.Parameter {
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

func (m *GCPScanAppEngineModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get required project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional credentials file
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	}

	// Create App Engine service
	appengineService, err := appengine.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create appengine service: %w", err)
	}

	// Create project resource first
	projectResource := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", projectID),
		AccountRef:   projectID,
		DisplayName:  projectID,
	}

	results := []plugin.Result{
		{
			Data: projectResource,
			Metadata: map[string]any{
				"module":   "app-engine-secrets",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}

	// Get App Engine application
	app, err := appengineService.Apps.Get(projectID).Do()
	if err != nil {
		// If App Engine is not enabled, return empty results
		slog.Debug("No App Engine application found", "error", err, "project", projectID)
		return results, nil
	}

	// List all services
	servicesCall := appengineService.Apps.Services.List(projectID)
	servicesResp, err := servicesCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list App Engine services in project: %w", err)
	}

	// Iterate through services and versions
	for _, service := range servicesResp.Services {
		versionsCall := appengineService.Apps.Services.Versions.List(projectID, service.Id)
		versionsResp, err := versionsCall.Do()
		if err != nil {
			slog.Error("Failed to list versions for App Engine service", "error", err, "service", service.Id)
			continue
		}

		for _, version := range versionsResp.Versions {
			// Create CloudResource for the version
			gcpAppEngineVersion := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "appengine.googleapis.com/Application",
				ResourceID:   fmt.Sprintf("projects/%s/services/%s/versions/%s", projectID, service.Id, version.Id),
				AccountRef:   projectID,
				DisplayName:  fmt.Sprintf("%s-%s", service.Id, version.Id),
				Properties:   postProcessAppEngineApplication(app, service, version),
			}

			results = append(results, plugin.Result{
				Data: gcpAppEngineVersion,
				Metadata: map[string]any{
					"module":   "app-engine-secrets",
					"platform": "gcp",
					"type":     "appengine-version",
				},
			})

			// Extract secrets from environment variables
			if len(version.EnvVariables) > 0 {
				content, err := json.Marshal(version.EnvVariables)
				if err != nil {
					slog.Warn("Failed to marshal env variables", "error", err)
					continue
				}

				npInput := types.NpInput{
					Content: string(content),
					Provenance: types.NpProvenance{
						Platform:     "gcp",
						ResourceType: "appengine.googleapis.com/Application::EnvVariables",
						ResourceID:   fmt.Sprintf("projects/%s/services/%s/versions/%s", projectID, service.Id, version.Id),
						AccountID:    projectID,
					},
				}

				results = append(results, plugin.Result{
					Data: npInput,
					Metadata: map[string]any{
						"module":      "app-engine-secrets",
						"platform":    "gcp",
						"type":        "secrets-input",
						"scanner":     "noseyparker",
						"resource_id": fmt.Sprintf("projects/%s/services/%s/versions/%s", projectID, service.Id, version.Id),
					},
				})
			}
		}
	}

	return results, nil
}

// postProcessAppEngineApplication extracts relevant properties from App Engine resources
func postProcessAppEngineApplication(app *appengine.Application, service *appengine.Service, version *appengine.Version) map[string]any {
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

	// Construct public URL
	if app.DefaultHostname != "" {
		var publicURL string
		if service.Id == "default" {
			publicURL = fmt.Sprintf("https://%s-dot-%s", version.Id, app.DefaultHostname)
		} else {
			publicURL = fmt.Sprintf("https://%s-dot-%s-dot-%s", version.Id, service.Id, app.DefaultHostname)
		}
		properties["publicURL"] = publicURL
	}

	// Extract custom domains
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
