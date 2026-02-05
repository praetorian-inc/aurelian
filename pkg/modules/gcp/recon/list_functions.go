package recon

import (
	"fmt"
	"strconv"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListFunctionsModule{})
}

// GCPListFunctionsModule lists all Cloud Functions in a GCP project
type GCPListFunctionsModule struct{}

func (m *GCPListFunctionsModule) ID() string {
	return "functions-list"
}

func (m *GCPListFunctionsModule) Name() string {
	return "GCP List Functions"
}

func (m *GCPListFunctionsModule) Description() string {
	return "List all Cloud Functions in a GCP project."
}

func (m *GCPListFunctionsModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListFunctionsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListFunctionsModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListFunctionsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListFunctionsModule) References() []string {
	return []string{}
}

func (m *GCPListFunctionsModule) Parameters() []plugin.Parameter {
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

func (m *GCPListFunctionsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
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

	// Create Cloud Functions service
	functionsService, err := cloudfunctions.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud functions service: %w", err)
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
				"module":   "functions-list",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}

	// List all functions in all locations (using "-" wildcard)
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, "-")
	listReq := functionsService.Projects.Locations.Functions.List(parent)

	err = listReq.Pages(cfg.Context, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, function := range page.Functions {
			gcpFunction := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "cloudfunctions.googleapis.com/Function",
				ResourceID:   function.Name,
				AccountRef:   projectID,
				DisplayName:  function.Name,
				Properties:   postProcessFunction(function),
			}

			results = append(results, plugin.Result{
				Data: gcpFunction,
				Metadata: map[string]any{
					"module":   "functions-list",
					"platform": "gcp",
					"type":     "function",
				},
			})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list functions in location: %w", err)
	}

	return results, nil
}

// postProcessFunction extracts relevant properties from a CloudFunction
func postProcessFunction(function *cloudfunctions.CloudFunction) map[string]any {
	properties := map[string]any{
		"name":                 function.Name,
		"description":          function.Description,
		"status":               function.Status,
		"version":              strconv.FormatInt(function.VersionId, 10),
		"entryPoint":           function.EntryPoint,
		"runtime":              function.Runtime,
		"serviceAccountEmail":  function.ServiceAccountEmail,
		"labels":               function.Labels,
		"environmentVariables": function.EnvironmentVariables,
		"maxInstances":         function.MaxInstances,
		"minInstances":         function.MinInstances,
		"vpcConnector":         function.VpcConnector,
		"ingressSettings":      function.IngressSettings,
	}
	if function.HttpsTrigger != nil && function.HttpsTrigger.Url != "" {
		properties["publicURL"] = function.HttpsTrigger.Url
	}
	return properties
}
