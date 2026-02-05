package recon

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/run/v2"
)

func init() {
	plugin.Register(&GCPListCloudRunModule{})
}

type GCPListCloudRunModule struct{}

func (m *GCPListCloudRunModule) ID() string {
	return "gcp-list-cloud-run"
}

func (m *GCPListCloudRunModule) Name() string {
	return "GCP List Cloud Run"
}

func (m *GCPListCloudRunModule) Description() string {
	return "List all Cloud Run services in a GCP project."
}

func (m *GCPListCloudRunModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListCloudRunModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListCloudRunModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListCloudRunModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListCloudRunModule) References() []string {
	return []string{}
}

func (m *GCPListCloudRunModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "credentials",
			Description: "Path to GCP credentials JSON file",
			Type:        "string",
			Required:    false,
		},
	}
}

func (m *GCPListCloudRunModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsPath, ok := cfg.Args["credentials"].(string); ok && credsPath != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsPath))
	}

	// Create Cloud Run service client
	runService, err := run.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud run service: %w", err)
	}

	// Create Compute service client for region listing
	regionService, err := compute.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}

	// List all regions in the project
	regionsCall := regionService.Regions.List(projectID)
	regionsResp, err := regionsCall.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list regions in project")
	}

	// Use semaphore to limit concurrent API calls
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []plugin.Result

	// Iterate through all regions and list Cloud Run services
	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionID string) {
			defer wg.Done()
			defer func() { <-sem }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, regionID)
			servicesCall := runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()

			if err == nil && servicesResp != nil {
				for _, service := range servicesResp.Services {
					cloudRunService := &output.CloudResource{
						Platform:     "gcp",
						ResourceType: "run.googleapis.com/Service",
						ResourceID:   service.Name,
						AccountRef:   projectID,
						DisplayName:  service.Name,
						Properties:   postProcessCloudRunService(service),
					}

					mu.Lock()
					results = append(results, plugin.Result{
						Data: cloudRunService,
						Metadata: map[string]any{
							"region": regionID,
						},
					})
					mu.Unlock()
				}
			} else if err != nil {
				slog.Error("Failed to list Cloud Run services in region", "error", err, "region", regionID)
			}
		}(region.Name)
	}

	wg.Wait()

	return results, nil
}

// postProcessCloudRunService extracts relevant properties from a Cloud Run service
func postProcessCloudRunService(service *run.GoogleCloudRunV2Service) map[string]any {
	properties := map[string]any{
		"name":      service.Name,
		"namespace": service.Annotations["cloud.googleapis.com/namespace"],
		"labels":    service.Labels,
	}
	properties["uid"] = service.Annotations["cloud.googleapis.com/uid"]
	properties["publicURLs"] = service.Urls

	if service.Template != nil {
		properties["serviceAccountName"] = service.Template.ServiceAccount
		if len(service.Template.Containers) > 0 {
			container := service.Template.Containers[0]
			properties["image"] = container.Image
			properties["command"] = container.Command
			properties["args"] = container.Args
			properties["workingDir"] = container.WorkingDir
		}
	}

	return properties
}
