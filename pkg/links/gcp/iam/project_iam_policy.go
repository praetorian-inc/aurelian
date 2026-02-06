package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// FILE INFO:
// GcpProjectIamPolicyLink - Extract IAM policy from a GCP project for analysis

// IAMPolicyData represents the IAM policy data for a project
type IAMPolicyData struct {
	ProjectId   string                          `json:"project_id"`
	ProjectName string                          `json:"project_name"`
	Policy      *cloudresourcemanager.Policy    `json:"policy"`
	Bindings    []*cloudresourcemanager.Binding `json:"bindings"`
	AccountRef  string                          `json:"account_ref"`
}

type GcpProjectIamPolicyLink struct {
	*base.NativeGCPLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to extract IAM policy from a GCP project
func NewGcpProjectIamPolicyLink(args map[string]any) *GcpProjectIamPolicyLink {
	link := &GcpProjectIamPolicyLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-project-iam-policy", args),
	}

	// Initialize resource manager service
	resourceManagerService, err := cloudresourcemanager.NewService(context.Background(), link.ClientOptions()...)
	if err != nil {
		slog.Error("Failed to create resource manager service", "error", err)
	}
	link.resourceManagerService = resourceManagerService

	return link
}

func (g *GcpProjectIamPolicyLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpProjectIamPolicyLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}

	slog.Debug("GcpProjectIamPolicyLink received resource", "type", resource.ResourceType, "name", resource.ResourceID)

	// Only process project resources
	if resource.ResourceType != "gcp_project" {
		slog.Debug("Skipping non-project resource", "type", resource.ResourceType, "name", resource.ResourceID)
		return nil, nil
	}

	projectId := resource.ResourceID
	slog.Debug("Extracting IAM policy for project", "project", projectId)

	// Get IAM policy for the project
	policy, err := g.resourceManagerService.Projects.GetIamPolicy(projectId, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, fmt.Sprintf("failed to get IAM policy for project %s", projectId))
	}

	// Create IAM policy data structure
	policyData := IAMPolicyData{
		ProjectId:   projectId,
		ProjectName: resource.DisplayName,
		Policy:      policy,
		Bindings:    policy.Bindings,
		AccountRef:  resource.AccountRef,
	}

	// Create a new cloud resource for the IAM policy data
	iamResource := &output.CloudResource{
		ResourceID:   fmt.Sprintf("%s-iam-policy", projectId),
		DisplayName:  fmt.Sprintf("IAM Policy - %s", projectId),
		ResourceType: "IAMPolicy",
		Region:       resource.Region,
		Platform:     "gcp",
		AccountRef:   resource.AccountRef,
		Properties: map[string]any{
			"project_id":   projectId,
			"project_name": resource.DisplayName,
			"policy_data":  policyData,
			"bindings":     policy.Bindings,
		},
	}

	slog.Debug("Extracted IAM policy",
		"project", projectId,
		"bindings_count", len(policy.Bindings))

	return []any{iamResource}, nil
}
