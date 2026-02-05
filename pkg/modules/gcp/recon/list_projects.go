package recon

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListProjectsModule{})
}

// GCPListProjectsModule lists all projects in a GCP organization
type GCPListProjectsModule struct{}

func (m *GCPListProjectsModule) ID() string {
	return "projects-list"
}

func (m *GCPListProjectsModule) Name() string {
	return "GCP List Projects"
}

func (m *GCPListProjectsModule) Description() string {
	return "List all projects in a GCP organization."
}

func (m *GCPListProjectsModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListProjectsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListProjectsModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListProjectsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListProjectsModule) References() []string {
	return []string{}
}

func (m *GCPListProjectsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "org",
			Description: "GCP organization ID (e.g., 123456789012 or organizations/123456789012)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "creds-file",
			Description: "Path to GCP service account credentials JSON file",
			Type:        "string",
		},
		{
			Name:        "filter-sys-projects",
			Description: "Filter out system projects (starting with sys-)",
			Type:        "bool",
			Default:     false,
		},
	}
}

func (m *GCPListProjectsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get organization parameter
	orgParam, ok := cfg.Args["org"].(string)
	if !ok || orgParam == "" {
		return nil, fmt.Errorf("org parameter is required")
	}

	// Normalize org parameter
	orgName := orgParam
	if !strings.HasPrefix(orgName, "organizations/") {
		orgName = "organizations/" + orgName
	}

	// Get optional parameters
	credsFile, _ := cfg.Args["creds-file"].(string)
	filterSysProjects, _ := cfg.Args["filter-sys-projects"].(bool)

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

	// Create resource manager service
	resourceManagerService, err := cloudresourcemanager.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	// First, get organization info
	org, err := resourceManagerService.Organizations.Get(orgName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get organization %s: %w", orgName, err)
	}

	// Create organization resource
	orgResource := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Organization",
		ResourceID:   org.Name,
		AccountRef:   org.Name,
		DisplayName:  org.DisplayName,
		Properties: map[string]any{
			"lifecycleState": org.LifecycleState,
			"creationTime":   org.CreationTime,
		},
	}

	// List all projects in the organization
	var projects []*output.CloudResource
	listReq := resourceManagerService.Projects.List()
	err = listReq.Pages(cfg.Context, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if filterSysProjects && strings.HasPrefix(project.ProjectId, "sys-") {
				continue
			}

			projectResource := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "cloudresourcemanager.googleapis.com/Project",
				ResourceID:   fmt.Sprintf("projects/%s", project.ProjectId),
				AccountRef:   fmt.Sprintf("%s/%s", project.Parent.Type, project.Parent.Id),
				DisplayName:  project.Name,
				Properties: map[string]any{
					"projectNumber":  strconv.FormatInt(project.ProjectNumber, 10),
					"lifecycleState": project.LifecycleState,
					"parentType":     project.Parent.Type,
					"parentId":       project.Parent.Id,
					"labels":         project.Labels,
				},
			}
			projects = append(projects, projectResource)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list projects in organization %s: %w", orgName, err)
	}

	// Return results - organization first, then all projects
	results := []plugin.Result{
		{
			Data:     orgResource,
			Metadata: map[string]any{
				"module":   "projects-list",
				"platform": "gcp",
				"type":     "organization",
			},
		},
	}

	for _, project := range projects {
		results = append(results, plugin.Result{
			Data:     project,
			Metadata: map[string]any{
				"module":   "projects-list",
				"platform": "gcp",
				"type":     "project",
			},
		})
	}

	return results, nil
}
