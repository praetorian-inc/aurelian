package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/run/v2"
)

func init() {
	plugin.Register(&GCPCloudRunSecretsModule{})
}

// GCPCloudRunSecretsModule lists all Cloud Run services in a GCP project and scans them for secrets
type GCPCloudRunSecretsModule struct{}

func (m *GCPCloudRunSecretsModule) ID() string {
	return "cloud-run-secrets"
}

func (m *GCPCloudRunSecretsModule) Name() string {
	return "GCP Scan Cloud Run Secrets"
}

func (m *GCPCloudRunSecretsModule) Description() string {
	return "List all Cloud Run services in a GCP project and scan them for secrets."
}

func (m *GCPCloudRunSecretsModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPCloudRunSecretsModule) Category() plugin.Category {
	return plugin.CategorySecrets
}

func (m *GCPCloudRunSecretsModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPCloudRunSecretsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPCloudRunSecretsModule) References() []string {
	return []string{}
}

func (m *GCPCloudRunSecretsModule) Parameters() []plugin.Parameter {
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

func (m *GCPCloudRunSecretsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
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

	// Create Cloud Run and Compute services
	runService, err := run.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud run service: %w", err)
	}

	regionService, err := compute.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	var results []plugin.Result

	// List all regions
	regionsCall := regionService.Regions.List(projectID)
	regionsResp, err := regionsCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list regions in project: %w", err)
	}

	// Concurrent processing with semaphore
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionID string) {
			defer wg.Done()
			defer func() { <-sem }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, regionID)
			servicesCall := runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()
			if err != nil {
				slog.Error("Failed to list Cloud Run services in region", "error", err, "region", regionID)
				return
			}

			if servicesResp == nil {
				return
			}

			for _, service := range servicesResp.Services {
				// Get full service details for secret extraction
				svc, err := runService.Projects.Locations.Services.Get(service.Name).Do()
				if err != nil {
					slog.Error("Failed to get Cloud Run service details", "error", err, "service", service.Name)
					continue
				}

				// Extract secrets from service
				secretResults := extractSecretsFromService(svc, projectID, regionID)

				mu.Lock()
				results = append(results, secretResults...)
				mu.Unlock()
			}
		}(region.Name)
	}

	wg.Wait()

	return results, nil
}

// extractSecretsFromService extracts environment variables and commands from a Cloud Run service
func extractSecretsFromService(svc *run.GoogleCloudRunV2Service, projectID, region string) []plugin.Result {
	var results []plugin.Result

	if svc.Template == nil {
		return results
	}

	for _, container := range svc.Template.Containers {
		if container == nil {
			continue
		}

		// Extract environment variables
		if len(container.Env) > 0 {
			if envContent, err := json.Marshal(container.Env); err == nil {
				results = append(results, plugin.Result{
					Data: map[string]any{
						"content": string(envContent),
						"provenance": map[string]any{
							"platform":      "gcp",
							"resource_type": "run.googleapis.com/Service::EnvVariables",
							"resource_id":   svc.Name,
							"region":        region,
							"account_id":    projectID,
						},
					},
					Metadata: map[string]any{
						"module":   "cloud-run-secrets",
						"platform": "gcp",
						"type":     "secret_content",
						"source":   "environment_variables",
					},
				})
			}
		}

		// Extract command and args
		var commandContent strings.Builder
		if len(container.Command) > 0 {
			commandContent.WriteString(strings.Join(container.Command, " "))
		}
		if len(container.Args) > 0 {
			if commandContent.Len() > 0 {
				commandContent.WriteString(" ")
			}
			commandContent.WriteString(strings.Join(container.Args, " "))
		}

		if commandContent.Len() > 0 {
			results = append(results, plugin.Result{
				Data: map[string]any{
					"content": commandContent.String(),
					"provenance": map[string]any{
						"platform":      "gcp",
						"resource_type": "run.googleapis.com/Service::Command",
						"resource_id":   svc.Name,
						"region":        region,
						"account_id":    projectID,
					},
				},
				Metadata: map[string]any{
					"module":   "cloud-run-secrets",
					"platform": "gcp",
					"type":     "secret_content",
					"source":   "command",
				},
			})
		}
	}

	return results
}
