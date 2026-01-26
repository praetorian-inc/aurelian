package iam

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
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
	Violations  []PrimitiveRoleViolation `json:"violations"`
	Summary     PrimitiveRolesSummary    `json:"summary"`
}

// PrimitiveRolesSummary provides summary statistics
type PrimitiveRolesSummary struct {
	TotalViolations   int `json:"total_violations"`
	OwnerRoles        int `json:"owner_roles"`
	EditorRoles       int `json:"editor_roles"`
	ViewerRoles       int `json:"viewer_roles"`
	ProjectsAffected  int `json:"projects_affected"`
}

type GcpPrimitiveRolesAnalyzer struct {
	*base.GcpBaseLink
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
func NewGcpPrimitiveRolesAnalyzer(configs ...cfg.Config) chain.Link {
	g := &GcpPrimitiveRolesAnalyzer{
		violations:        make([]PrimitiveRoleViolation, 0),
		projectsProcessed: make(map[string]string),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpPrimitiveRolesAnalyzer) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		cfg.NewParam[bool]("exclude-default-service-accounts", "exclude default service accounts from primitive role detection").WithDefault(false),
	)
	return params
}

func (g *GcpPrimitiveRolesAnalyzer) Initialize() error {
	return g.GcpBaseLink.Initialize()
}

func (g *GcpPrimitiveRolesAnalyzer) Process(resource tab.GCPResource) error {
	slog.Debug("GcpPrimitiveRolesAnalyzer received resource", "type", string(resource.ResourceType), "name", resource.Name)

	// Only process IAM policy resources
	if string(resource.ResourceType) != "IAMPolicy" {
		slog.Debug("Skipping non-IAM policy resource", "type", string(resource.ResourceType), "name", resource.Name)
		return nil
	}

	return g.processIAMPolicy(resource)
}

func (g *GcpPrimitiveRolesAnalyzer) processIAMPolicy(resource tab.GCPResource) error {
	properties := resource.Properties
	if properties == nil {
		return fmt.Errorf("no properties found for IAM policy resource")
	}

	policyDataRaw, ok := properties["policy_data"]
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
	excludeDefaultServiceAccounts, err := cfg.As[bool](g.Arg("exclude-default-service-accounts"))
	if err != nil {
		excludeDefaultServiceAccounts = false // Default to false if config error
	}

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

func (g *GcpPrimitiveRolesAnalyzer) Complete() error {
	// Generate the complete finding only if we have violations
	if len(g.violations) == 0 {
		slog.Info("No primitive role violations found")
		return nil
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

	g.Send(finding)
	return nil
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