package iam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/iam/v1"
)

// DefaultServiceAccountViolation represents a single default service account violation
type DefaultServiceAccountViolation struct {
	ServiceAccountEmail string   `json:"service_account_email"`
	ServiceAccountType  string   `json:"service_account_type"`
	ProjectId           string   `json:"project_id"`
	ProjectName         string   `json:"project_name"`
	Roles               []string `json:"roles"`
	RiskLevel           string   `json:"risk_level"`
	Description         string   `json:"description"`
	IsActive            bool     `json:"is_active"`
}

// DefaultServiceAccountFinding represents the complete security finding
type DefaultServiceAccountFinding struct {
	FindingData struct {
		Title          string `json:"title"`
		AttackCategory string `json:"attack_category"`
	} `json:"finding_data"`
	Violations []DefaultServiceAccountViolation `json:"violations"`
	Summary    DefaultServiceAccountSummary     `json:"summary"`
}

// DefaultServiceAccountSummary provides summary statistics
type DefaultServiceAccountSummary struct {
	TotalViolations       int `json:"total_violations"`
	ComputeDefaultSAs     int `json:"compute_default_sas"`
	AppEngineDefaultSAs   int `json:"appengine_default_sas"`
	ActiveServiceAccounts int `json:"active_service_accounts"`
	ProjectsAffected      int `json:"projects_affected"`
}

type GcpDefaultServiceAccountAnalyzer struct {
	*base.NativeGCPLink
	iamService        *iam.Service
	violations        []DefaultServiceAccountViolation
	projectsProcessed map[string]string // projectId -> projectName
}

// Default service account patterns that should be flagged
var defaultServiceAccountPatterns = map[string]string{
	"-compute@developer.gserviceaccount.com": "compute-default",
	"@appspot.gserviceaccount.com":           "appengine-default",
}

// NewGcpDefaultServiceAccountAnalyzer creates a link to analyze default service account violations
func NewGcpDefaultServiceAccountAnalyzer(args map[string]any) *GcpDefaultServiceAccountAnalyzer {
	link := &GcpDefaultServiceAccountAnalyzer{
		NativeGCPLink:     base.NewNativeGCPLink("gcp-default-sa-analyzer", args),
		violations:        make([]DefaultServiceAccountViolation, 0),
		projectsProcessed: make(map[string]string),
	}

	// Initialize IAM service
	iamService, err := iam.NewService(context.Background(), link.ClientOptions()...)
	if err != nil {
		slog.Error("Failed to create IAM service", "error", common.HandleGcpError(err, "failed to create IAM service"))
	}
	link.iamService = iamService

	return link
}

func (g *GcpDefaultServiceAccountAnalyzer) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpDefaultServiceAccountAnalyzer) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}

	slog.Debug("GcpDefaultServiceAccountAnalyzer received resource", "type", resource.ResourceType, "name", resource.ResourceID)

	if resource.ResourceType == "IAMPolicy" {
		if err := g.processIAMPolicy(resource); err != nil {
			return nil, err
		}
	} else {
		slog.Debug("Skipping unsupported resource type", "type", resource.ResourceType, "name", resource.ResourceID)
	}

	return nil, nil
}

func (g *GcpDefaultServiceAccountAnalyzer) processIAMPolicy(resource *output.CloudResource) error {
	// resource.Properties is already map[string]any, no type assertion needed
	data := resource.Properties
	if data == nil {
		return fmt.Errorf("nil properties for IAM policy resource")
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

	slog.Debug("Analyzing IAM policy for default service accounts", "project", policyData.ProjectId)

	// Analyze IAM policy bindings for default service accounts
	for _, binding := range policyData.Bindings {
		for _, member := range binding.Members {
			if g.isDefaultServiceAccount(member) {
				// Check if this default service account has risky roles
				if g.hasRiskyRole(binding.Role) {
					violation := DefaultServiceAccountViolation{
						ServiceAccountEmail: member,
						ServiceAccountType:  g.categorizeDefaultServiceAccount(member),
						ProjectId:           policyData.ProjectId,
						ProjectName:         policyData.ProjectName,
						Roles:               []string{binding.Role},
						RiskLevel:           g.determineRiskLevelFromRole(binding.Role),
						Description:         g.generateDescriptionFromRole(member, binding.Role),
						IsActive:            true, // Assume active if it has IAM bindings
					}

					g.violations = append(g.violations, violation)
					slog.Debug("Found default service account violation",
						"sa_email", member,
						"project", policyData.ProjectId,
						"role", binding.Role,
						"type", violation.ServiceAccountType)
				}
			}
		}
	}

	return nil
}

func (g *GcpDefaultServiceAccountAnalyzer) isDefaultServiceAccount(member string) bool {
	// Handle serviceAccount: prefix
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	for pattern := range defaultServiceAccountPatterns {
		if strings.Contains(email, pattern) {
			return true
		}
	}
	return false
}

func (g *GcpDefaultServiceAccountAnalyzer) categorizeDefaultServiceAccount(member string) string {
	// Handle serviceAccount: prefix
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	for pattern, saType := range defaultServiceAccountPatterns {
		if strings.Contains(email, pattern) {
			return saType
		}
	}
	return "unknown-default"
}

func (g *GcpDefaultServiceAccountAnalyzer) hasRiskyRole(role string) bool {
	// Flag roles that give broad permissions
	riskyRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/viewer", // Even viewer can be risky for default SAs
	}

	for _, riskyRole := range riskyRoles {
		if role == riskyRole {
			return true
		}
	}
	return false
}

func (g *GcpDefaultServiceAccountAnalyzer) determineRiskLevelFromRole(role string) string {
	switch role {
	case "roles/owner", "roles/editor":
		return "high"
	case "roles/viewer":
		return "medium"
	default:
		return "low"
	}
}

func (g *GcpDefaultServiceAccountAnalyzer) generateDescriptionFromRole(member, role string) string {
	email := member
	if strings.HasPrefix(member, "serviceAccount:") {
		email = strings.TrimPrefix(member, "serviceAccount:")
	}

	saType := g.categorizeDefaultServiceAccount(member)
	switch saType {
	case "compute-default":
		return fmt.Sprintf("Default Compute Engine service account (%s) has %s role which provides broad permissions and should be replaced with a custom service account with minimal permissions", email, role)
	case "appengine-default":
		return fmt.Sprintf("Default App Engine service account (%s) has %s role which provides broad permissions and should be replaced with a custom service account with minimal permissions", email, role)
	default:
		return fmt.Sprintf("Default service account (%s) has %s role and should be replaced with a custom service account with minimal permissions", email, role)
	}
}

func (g *GcpDefaultServiceAccountAnalyzer) Complete(ctx context.Context) ([]any, error) {
	// Generate the complete finding only if we have violations
	if len(g.violations) == 0 {
		slog.Info("No default service account violations found")
		return nil, nil
	}

	summary := g.calculateSummary()
	finding := DefaultServiceAccountFinding{
		FindingData: struct {
			Title          string `json:"title"`
			AttackCategory string `json:"attack_category"`
		}{
			Title:          "GCP Default Service Account Violations",
			AttackCategory: "Privilege Escalation",
		},
		Violations: g.violations,
		Summary:    summary,
	}

	slog.Info("Generated default service account finding",
		"total_violations", summary.TotalViolations,
		"projects_affected", summary.ProjectsAffected,
		"compute_default", summary.ComputeDefaultSAs,
		"appengine_default", summary.AppEngineDefaultSAs,
		"active_accounts", summary.ActiveServiceAccounts)

	resource := &output.CloudResource{
		ResourceID:   fmt.Sprintf("gcp-default-sa-finding-%s", finding.FindingData.Title),
		DisplayName:  finding.FindingData.Title,
		ResourceType: "gcp_default_sa_finding",
		Region:       "global",
		Platform:     "gcp",
		Properties:   map[string]any{"finding": finding},
	}

	return []any{resource}, nil
}

func (g *GcpDefaultServiceAccountAnalyzer) calculateSummary() DefaultServiceAccountSummary {
	summary := DefaultServiceAccountSummary{
		TotalViolations:  len(g.violations),
		ProjectsAffected: len(g.projectsProcessed),
	}

	for _, violation := range g.violations {
		switch violation.ServiceAccountType {
		case "compute-default":
			summary.ComputeDefaultSAs++
		case "appengine-default":
			summary.AppEngineDefaultSAs++
		}

		if violation.IsActive {
			summary.ActiveServiceAccounts++
		}
	}

	return summary
}
