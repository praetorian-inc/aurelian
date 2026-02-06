package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// PrimitiveRoleViolation represents a single primitive role violation
type PrimitiveRoleViolation struct {
	Principal     string `json:"principal"`
	PrincipalType string `json:"principal_type"`
	ProjectId     string `json:"project_id"`
	ProjectName   string `json:"project_name"`
	Role          string `json:"role"`
	RoleName      string `json:"role_name"`
	RiskLevel     string `json:"risk_level"`
	Description   string `json:"description"`
}

// PrimitiveRolesFinding represents the complete security finding
type PrimitiveRolesFinding struct {
	FindingData struct {
		Title          string `json:"title"`
		AttackCategory string `json:"attack_category"`
	} `json:"finding_data"`
	Violations []PrimitiveRoleViolation `json:"violations"`
	Summary    PrimitiveRolesSummary    `json:"summary"`
}

// PrimitiveRolesSummary provides summary statistics
type PrimitiveRolesSummary struct {
	TotalViolations  int `json:"total_violations"`
	OwnerRoles       int `json:"owner_roles"`
	EditorRoles      int `json:"editor_roles"`
	ViewerRoles      int `json:"viewer_roles"`
	ProjectsAffected int `json:"projects_affected"`
}

type GcpPrimitiveRolesAnalyzer struct {
	*base.NativeGCPLink
	violations        []PrimitiveRoleViolation
	projectsProcessed map[string]string // projectId -> projectName
}

// Primitive/basic roles that violate least privilege principle
var primitiveRoles = map[string]string{
	"roles/owner":  "Owner",
	"roles/editor": "Editor",
	"roles/viewer": "Viewer",
}

// NewGcpPrimitiveRolesAnalyzer creates a link to analyze primitive roles violations
func NewGcpPrimitiveRolesAnalyzer(args map[string]any) *GcpPrimitiveRolesAnalyzer {
	return &GcpPrimitiveRolesAnalyzer{
		NativeGCPLink:     base.NewNativeGCPLink("gcp-primitive-roles-analyzer", args),
		violations:        make([]PrimitiveRoleViolation, 0),
		projectsProcessed: make(map[string]string),
	}
}

func (g *GcpPrimitiveRolesAnalyzer) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[bool]("exclude-default-service-accounts", "exclude default service accounts from primitive role detection", plugin.WithDefault(false)),
	)
	return params
}

func (g *GcpPrimitiveRolesAnalyzer) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}

	slog.Debug("GcpPrimitiveRolesAnalyzer received resource", "type", resource.ResourceType, "name", resource.ResourceID)

	// Only process IAM policy resources
	if resource.ResourceType != "IAMPolicy" {
		slog.Debug("Skipping non-IAM policy resource", "type", resource.ResourceType, "name", resource.ResourceID)
		return nil, nil
	}

	if err := g.processIAMPolicy(resource); err != nil {
		return nil, err
	}

	return nil, nil
}

func (g *GcpPrimitiveRolesAnalyzer) processIAMPolicy(resource *output.CloudResource) error {
	data := resource.Properties
	if data == nil {
		return fmt.Errorf("properties is nil for IAM policy resource")
	}

	policyDataRaw, ok := data["policy_data"]
	if !ok {
		return fmt.Errorf("missing policy_data in IAM policy resource")
	}

	policyData, ok := policyDataRaw.(IAMPolicyData)
	if !ok {
		slog.Debug("Could not convert policy data to IAMPolicyData struct")
		return nil
	}

	// Store project info
	g.projectsProcessed[policyData.ProjectId] = policyData.ProjectName

	// Analyze the IAM policy for primitive role violations
	g.analyzeIAMPolicy(&policyData)

	return nil
}

func (g *GcpPrimitiveRolesAnalyzer) analyzeIAMPolicy(policyData *IAMPolicyData) {
	// Check if default service accounts should be excluded
	excludeDefaultServiceAccounts := g.ArgBool("exclude-default-service-accounts", false)

	for _, binding := range policyData.Bindings {
		// Check for primitive roles violations
		if roleName, isPrimitiveRole := primitiveRoles[binding.Role]; isPrimitiveRole {
			for _, member := range binding.Members {
				principalType := categorizePrincipal(member)

				// Skip default service accounts if exclusion is enabled
				if excludeDefaultServiceAccounts && principalType == "service_account" && isDefaultServiceAccount(member) {
					slog.Debug("Skipping default service account due to exclusion flag", "principal", member)
					continue
				}

				violation := PrimitiveRoleViolation{
					Principal:     member,
					PrincipalType: principalType,
					ProjectId:     policyData.ProjectId,
					ProjectName:   policyData.ProjectName,
					Role:          binding.Role,
					RoleName:      roleName,
					RiskLevel:     determineRiskLevel(binding.Role),
					Description:   fmt.Sprintf("Principal has primitive role '%s' (%s) which violates least privilege principle", binding.Role, roleName),
				}

				g.violations = append(g.violations, violation)
				slog.Debug("Found primitive role violation",
					"principal", member,
					"role", binding.Role,
					"project", policyData.ProjectId)
			}
		}
	}
}

func (g *GcpPrimitiveRolesAnalyzer) Complete(ctx context.Context) ([]any, error) {
	// Generate the complete finding only if we have violations
	if len(g.violations) == 0 {
		slog.Info("No primitive role violations found")
		return nil, nil
	}

	summary := g.calculateSummary()
	finding := PrimitiveRolesFinding{
		FindingData: struct {
			Title          string `json:"title"`
			AttackCategory string `json:"attack_category"`
		}{
			Title:          "GCP Primitive IAM Roles Violations",
			AttackCategory: "Privilege Escalation",
		},
		Violations: g.violations,
		Summary:    summary,
	}

	slog.Info("Generated primitive roles finding",
		"total_violations", summary.TotalViolations,
		"projects_affected", summary.ProjectsAffected,
		"owner_roles", summary.OwnerRoles,
		"editor_roles", summary.EditorRoles,
		"viewer_roles", summary.ViewerRoles)

	resource := &output.CloudResource{
		ResourceID:   fmt.Sprintf("gcp-primitive-roles-finding-%s", finding.FindingData.Title),
		DisplayName:  finding.FindingData.Title,
		ResourceType: "gcp_primitive_roles_finding",
		Region:       "global",
		Platform:     "gcp",
		Properties:   map[string]any{"finding": finding},
	}

	return []any{resource}, nil
}

func (g *GcpPrimitiveRolesAnalyzer) calculateSummary() PrimitiveRolesSummary {
	summary := PrimitiveRolesSummary{
		TotalViolations:  len(g.violations),
		ProjectsAffected: len(g.projectsProcessed),
	}

	for _, violation := range g.violations {
		switch violation.Role {
		case "roles/owner":
			summary.OwnerRoles++
		case "roles/editor":
			summary.EditorRoles++
		case "roles/viewer":
			summary.ViewerRoles++
		}
	}

	return summary
}

// Helper functions

func determineRiskLevel(role string) string {
	switch role {
	case "roles/owner", "roles/editor":
		return "high"
	case "roles/viewer":
		return "medium"
	default:
		return "low"
	}
}

// categorizePrincipal and generateUUID are already defined in iam_principals_analyzer.go
// We'll reuse those functions
