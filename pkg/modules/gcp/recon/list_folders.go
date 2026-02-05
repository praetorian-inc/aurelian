package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"golang.org/x/oauth2/google"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListFoldersModule{})
}

// GCPListFoldersModule lists all folders in a GCP organization
type GCPListFoldersModule struct{}

func (m *GCPListFoldersModule) ID() string {
	return "folders-list"
}

func (m *GCPListFoldersModule) Name() string {
	return "GCP List Folders"
}

func (m *GCPListFoldersModule) Description() string {
	return "List all folders in a GCP organization."
}

func (m *GCPListFoldersModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListFoldersModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListFoldersModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListFoldersModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListFoldersModule) References() []string {
	return []string{}
}

func (m *GCPListFoldersModule) Parameters() []plugin.Parameter {
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
	}
}

func (m *GCPListFoldersModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
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

	// Setup GCP client options
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	} else {
		// Attempt to use application default credentials
		_, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot find default credentials (use --creds-file): %w", err)
		}
	}

	// Create resource manager service (v2 for folders API)
	resourceManagerService, err := cloudresourcemanagerv2.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager v2 service: %w", err)
	}

	// List all folders in the organization
	var folders []*output.CloudResource
	listReq := resourceManagerService.Folders.List().Parent(orgName)
	err = listReq.Pages(ctx, func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			folderResource := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "cloudresourcemanager.googleapis.com/Folder",
				ResourceID:   folder.Name, // "folders/123456789"
				AccountRef:   folder.Parent,
				DisplayName:  folder.DisplayName,
				Properties: map[string]any{
					"lifecycleState": folder.LifecycleState,
					"createTime":     folder.CreateTime,
				},
			}
			folders = append(folders, folderResource)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list folders in organization %s: %w", orgName, err)
	}

	// Convert folders to results
	var results []plugin.Result
	for _, folder := range folders {
		results = append(results, plugin.Result{
			Data: folder,
			Metadata: map[string]any{
				"module":   "folders-list",
				"platform": "gcp",
				"type":     "folder",
			},
		})
	}

	return results, nil
}
