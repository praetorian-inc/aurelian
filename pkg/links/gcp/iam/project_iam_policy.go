package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
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
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to extract IAM policy from a GCP project
func NewGcpProjectIamPolicyLink(configs ...cfg.Config) chain.Link {
	g := &GcpProjectIamPolicyLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpProjectIamPolicyLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpProjectIamPolicyLink) Process(resource tab.GCPResource) error {
	slog.Debug("GcpProjectIamPolicyLink received resource", "type", resource.ResourceType, "name", resource.Name)

	// Only process project resources
	if resource.ResourceType != tab.GCPResourceProject {
		slog.Debug("Skipping non-project resource", "type", resource.ResourceType, "name", resource.Name)
		return nil
	}

	projectId := resource.Name
	slog.Debug("Extracting IAM policy for project", "project", projectId)

	// Get IAM policy for the project
	policy, err := g.resourceManagerService.Projects.GetIamPolicy(projectId, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return common.HandleGcpError(err, fmt.Sprintf("failed to get IAM policy for project %s", projectId))
	}

	// Create IAM policy data structure
	policyData := IAMPolicyData{
		ProjectId:   projectId,
		ProjectName: resource.DisplayName,
		Policy:      policy,
		Bindings:    policy.Bindings,
		AccountRef:  resource.AccountRef,
	}

	// Create a new GCP resource for the IAM policy data
	iamResource, err := tab.NewGCPResource(
		fmt.Sprintf("%s-iam-policy", projectId), // resource name
		resource.AccountRef,                     // accountRef (organization or parent)
		tab.CloudResourceType("IAMPolicy"),      // custom resource type for IAM policies
		map[string]any{ // properties
			"project_id":   projectId,
			"project_name": resource.DisplayName,
			"policy_data":  policyData,
			"bindings":     policy.Bindings,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create IAM policy resource: %w", err)
	}

	iamResource.DisplayName = fmt.Sprintf("IAM Policy - %s", projectId)
	iamResource.Region = resource.Region

	slog.Debug("Extracted IAM policy",
		"project", projectId,
		"bindings_count", len(policy.Bindings))

	g.Send(iamResource)
	return nil
}
