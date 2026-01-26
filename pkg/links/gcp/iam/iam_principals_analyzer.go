package iam

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

// FILE INFO:
// GcpIamPrincipalsAnalyzer - Analyze IAM policies and service accounts for overprivileged principals

// Basic roles that are considered overprivileged
var basicRoles = map[string]string{
	"roles/owner":  "Owner",
	"roles/editor": "Editor",
	"roles/viewer": "Viewer",
}

// Overprivileged roles at project level
var overprivilegedProjectRoles = map[string]string{
	"roles/iam.serviceAccountUser": "Service Account User",
}

// RiskMetric represents individual risk assessment data
type RiskMetric struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand"`
	Result    string `json:"result"`
}

// IAMPrincipalViolation represents a violation by an IAM principal
type IAMPrincipalViolation struct {
	Principal       string   `json:"principal"`
	PrincipalType   string   `json:"principal_type"`
	ProjectId       string   `json:"project_id"`
	ProjectName     string   `json:"project_name"`
	ViolationType   string   `json:"violation_type"`
	Roles           []string `json:"roles"`
	RiskLevel       string   `json:"risk_level"`
	Description     string   `json:"description"`
}

// ComputeInstanceViolation represents a violation by a compute instance
type ComputeInstanceViolation struct {
	InstanceId          string   `json:"instance_id"`
	InstanceName        string   `json:"instance_name"`
	ProjectId           string   `json:"project_id"`
	Zone                string   `json:"zone"`
	ServiceAccountEmail string   `json:"service_account_email"`
	ServiceAccountType  string   `json:"service_account_type"`
	ViolationType       string   `json:"violation_type"`
	RiskLevel           string   `json:"risk_level"`
	Description         string   `json:"description"`
	Scopes              []string `json:"scopes"`
}

// OverprivilegedPrincipalsFinding represents the complete security finding
type OverprivilegedPrincipalsFinding struct {
	FindingData struct {
		Title          string `json:"title"`
		AttackCategory string `json:"attack_category"`
	} `json:"finding_data"`
	RiskData         []RiskMetric                   `json:"risk_data"`
	CVSS             string                         `json:"cvss"`
	Meta             string                         `json:"meta"`
	Principals       []IAMPrincipalViolation        `json:"principals"`
	ComputeInstances []ComputeInstanceViolation     `json:"compute_instances"`
	Summary          OverprivilegedSummary          `json:"summary"`
}

// OverprivilegedSummary provides summary statistics
type OverprivilegedSummary struct {
	TotalViolations       int `json:"total_violations"`
	BasicRoleViolations   int `json:"basic_role_violations"`
	ServiceAccountUserViolations int `json:"service_account_user_violations"`
	DefaultComputeSAViolations int `json:"default_compute_sa_violations"`
	ProjectsAffected      int `json:"projects_affected"`
}

type GcpIamPrincipalsAnalyzer struct {
	*base.GcpBaseLink
	iamPolicyData     map[string]*IAMPolicyData
	serviceAccountData map[string]*ComputeServiceAccountData
	violations        []IAMPrincipalViolation
	instanceViolations []ComputeInstanceViolation
	projectsProcessed  map[string]string // projectId -> projectName
}

// creates a link to analyze IAM principals for overprivileged access
func NewGcpIamPrincipalsAnalyzer(configs ...cfg.Config) chain.Link {
	g := &GcpIamPrincipalsAnalyzer{
		iamPolicyData:     make(map[string]*IAMPolicyData),
		serviceAccountData: make(map[string]*ComputeServiceAccountData),
		violations:        make([]IAMPrincipalViolation, 0),
		instanceViolations: make([]ComputeInstanceViolation, 0),
		projectsProcessed: make(map[string]string),
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpIamPrincipalsAnalyzer) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		cfg.NewParam[bool]("debug-violations", "generate test violations for debugging").WithDefault(false),
	)
	return params
}

func (g *GcpIamPrincipalsAnalyzer) Initialize() error {
	return g.GcpBaseLink.Initialize()
}

func (g *GcpIamPrincipalsAnalyzer) Process(resource tab.GCPResource) error {
	slog.Debug("GcpIamPrincipalsAnalyzer received resource", "type", string(resource.ResourceType), "name", resource.Name)

	switch string(resource.ResourceType) {
	case "IAMPolicy":
		return g.processIAMPolicy(resource)
	case "ComputeServiceAccount":
		return g.processComputeServiceAccount(resource)
	}
	return nil
}

func (g *GcpIamPrincipalsAnalyzer) processIAMPolicy(resource tab.GCPResource) error {
	properties := resource.Properties
	if properties == nil {
		return fmt.Errorf("no properties found for IAM policy resource")
	}

	policyDataRaw, ok := properties["policy_data"]
	if !ok {
		return fmt.Errorf("missing policy_data in IAM policy resource")
	}

	// Convert the policy data - this will be the IAMPolicyData struct
	policyData, ok := policyDataRaw.(IAMPolicyData)
	if !ok {
		slog.Debug("Could not convert policy data to IAMPolicyData struct")
		return nil
	}

	g.iamPolicyData[policyData.ProjectId] = &policyData
	g.projectsProcessed[policyData.ProjectId] = policyData.ProjectName

	// Analyze the IAM policy for violations
	g.analyzeIAMPolicy(&policyData)

	return nil
}

func (g *GcpIamPrincipalsAnalyzer) processComputeServiceAccount(resource tab.GCPResource) error {
	properties := resource.Properties
	if properties == nil {
		return fmt.Errorf("no properties found for service account resource")
	}

	saDataRaw, ok := properties["sa_data"]
	if !ok {
		return fmt.Errorf("missing sa_data in service account resource")
	}

	saData, ok := saDataRaw.(ComputeServiceAccountData)
	if !ok {
		slog.Debug("Could not convert SA data to ComputeServiceAccountData struct")
		return nil
	}

	key := fmt.Sprintf("%s-%s", saData.InstanceId, saData.ServiceAccountEmail)
	g.serviceAccountData[key] = &saData

	// Analyze service account for violations
	g.analyzeComputeServiceAccount(&saData)

	return nil
}

func (g *GcpIamPrincipalsAnalyzer) analyzeIAMPolicy(policyData *IAMPolicyData) {
	for _, binding := range policyData.Bindings {
		// Check for basic roles violations
		if roleName, isBasicRole := basicRoles[binding.Role]; isBasicRole {
			for _, member := range binding.Members {
				violation := IAMPrincipalViolation{
					Principal:       member,
					PrincipalType:   categorizePrincipal(member),
					ProjectId:       policyData.ProjectId,
					ProjectName:     policyData.ProjectName,
					ViolationType:   "basic_role",
					Roles:           []string{binding.Role},
					RiskLevel:       "high",
					Description:     fmt.Sprintf("Principal has basic role '%s' (%s) which violates least privilege principle", binding.Role, roleName),
				}
				g.violations = append(g.violations, violation)

				slog.Info("Detected basic role violation",
					"principal", member,
					"role", binding.Role,
					"project", policyData.ProjectId)
			}
		}

		// Check for overprivileged project roles
		if roleName, isOverprivileged := overprivilegedProjectRoles[binding.Role]; isOverprivileged {
			for _, member := range binding.Members {
				violation := IAMPrincipalViolation{
					Principal:       member,
					PrincipalType:   categorizePrincipal(member),
					ProjectId:       policyData.ProjectId,
					ProjectName:     policyData.ProjectName,
					ViolationType:   "service_account_user",
					Roles:           []string{binding.Role},
					RiskLevel:       "high",
					Description:     fmt.Sprintf("Principal has '%s' (%s) role at project level, allowing access to all service accounts", binding.Role, roleName),
				}
				g.violations = append(g.violations, violation)

				slog.Info("Detected Service Account User violation",
					"principal", member,
					"role", binding.Role,
					"project", policyData.ProjectId)
			}
		}
	}
}

func (g *GcpIamPrincipalsAnalyzer) analyzeComputeServiceAccount(saData *ComputeServiceAccountData) {
	// Check if this is a default compute service account
	if saData.IsDefaultSA && saData.ServiceAccountType == "default-compute" {
		// Check if this service account has Editor role by cross-referencing with IAM policy
		if policyData, exists := g.iamPolicyData[saData.ProjectId]; exists {
			if g.hasEditorRole(policyData, fmt.Sprintf("serviceAccount:%s", saData.ServiceAccountEmail)) {
				violation := ComputeInstanceViolation{
					InstanceId:          saData.InstanceId,
					InstanceName:        saData.InstanceName,
					ProjectId:           saData.ProjectId,
					Zone:                saData.Zone,
					ServiceAccountEmail: saData.ServiceAccountEmail,
					ServiceAccountType:  saData.ServiceAccountType,
					ViolationType:       "default_compute_sa_editor",
					RiskLevel:           "high",
					Description:         "Compute instance uses default service account with Editor role, violating least privilege",
					Scopes:              saData.Scopes,
				}
				g.instanceViolations = append(g.instanceViolations, violation)

				slog.Info("Detected default compute SA with Editor role",
					"instance", saData.InstanceName,
					"service_account", saData.ServiceAccountEmail,
					"project", saData.ProjectId)
			}
		}
	}
}

func (g *GcpIamPrincipalsAnalyzer) hasEditorRole(policyData *IAMPolicyData, member string) bool {
	for _, binding := range policyData.Bindings {
		if binding.Role == "roles/editor" {
			for _, bindingMember := range binding.Members {
				if bindingMember == member {
					return true
				}
			}
		}
	}
	return false
}

func (g *GcpIamPrincipalsAnalyzer) Complete() error {
	// Debug mode: Generate test violations to verify data flow
	debugMode, err := cfg.As[bool](g.Arg("debug-violations"))
	if err == nil && debugMode {
		slog.Info("Debug mode enabled: generating test violations")
		g.generateTestViolations()
	}

	// Generate the complete finding only if we have violations
	if len(g.violations) == 0 && len(g.instanceViolations) == 0 {
		slog.Info("No overprivileged principals found")
		return nil
	}

	summary := g.calculateSummary()
	finding := OverprivilegedPrincipalsFinding{
		FindingData: struct {
			Title          string `json:"title"`
			AttackCategory string `json:"attack_category"`
		}{
			Title:          "Overprivileged GCP IAM Principals",
			AttackCategory: "Privilege Escalation",
		},
		RiskData: []RiskMetric{
			{Name: "access_vector", Shorthand: "Av", Result: "(3) External"},
			{Name: "attack_feasibility", Shorthand: "Af", Result: "(3) Demonstrated"},
			{Name: "authentication", Shorthand: "Au", Result: "(2) User"},
			{Name: "compromise_impact", Shorthand: "Ci", Result: "(3) Complete"},
			{Name: "business_value", Shorthand: "Bv", Result: "(2) System"},
		},
		CVSS:             "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L",
		Meta:             fmt.Sprintf("cloud-%s", generateUUID()),
		Principals:       g.violations,
		ComputeInstances: g.instanceViolations,
		Summary:          summary,
	}

	slog.Info("Generated overprivileged principals finding",
		"total_violations", summary.TotalViolations,
		"projects_affected", summary.ProjectsAffected,
		"basic_role_violations", summary.BasicRoleViolations,
		"sa_user_violations", summary.ServiceAccountUserViolations,
		"compute_sa_violations", summary.DefaultComputeSAViolations)

	g.Send(finding)
	return nil
}

func (g *GcpIamPrincipalsAnalyzer) calculateSummary() OverprivilegedSummary {
	summary := OverprivilegedSummary{
		TotalViolations:  len(g.violations) + len(g.instanceViolations),
		ProjectsAffected: len(g.projectsProcessed),
	}

	for _, violation := range g.violations {
		switch violation.ViolationType {
		case "basic_role":
			summary.BasicRoleViolations++
		case "service_account_user":
			summary.ServiceAccountUserViolations++
		}
	}

	for _, violation := range g.instanceViolations {
		if violation.ViolationType == "default_compute_sa_editor" {
			summary.DefaultComputeSAViolations++
		}
	}

	return summary
}

// Helper functions

func categorizePrincipal(member string) string {
	if strings.HasPrefix(member, "user:") {
		return "user"
	}
	if strings.HasPrefix(member, "serviceAccount:") {
		return "service_account"
	}
	if strings.HasPrefix(member, "group:") {
		return "group"
	}
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		return "public"
	}
	return "unknown"
}

func generateUUID() string {
	// Simple UUID-like generation for demo purposes
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (g *GcpIamPrincipalsAnalyzer) generateTestViolations() {
	// Generate test IAM principal violations
	g.violations = append(g.violations, IAMPrincipalViolation{
		Principal:       "user:test-admin@example.com",
		PrincipalType:   "user",
		ProjectId:       "test-project-123",
		ProjectName:     "Test Project",
		ViolationType:   "basic_role",
		Roles:           []string{"roles/owner"},
		RiskLevel:       "high",
		Description:     "Principal has basic role 'roles/owner' (Owner) which violates least privilege principle",
	})

	g.violations = append(g.violations, IAMPrincipalViolation{
		Principal:       "serviceAccount:automation@test-project-123.iam.gserviceaccount.com",
		PrincipalType:   "service_account",
		ProjectId:       "test-project-123",
		ProjectName:     "Test Project",
		ViolationType:   "sa_user_project",
		Roles:           []string{"roles/iam.serviceAccountUser"},
		RiskLevel:       "medium",
		Description:     "Principal has Service Account User role at project level which enables broad privilege escalation",
	})

	// Generate test compute instance violations
	g.instanceViolations = append(g.instanceViolations, ComputeInstanceViolation{
		InstanceId:          "123456789",
		InstanceName:        "test-instance-1",
		ProjectId:           "test-project-123",
		Zone:                "us-central1-a",
		ServiceAccountEmail: "123456789-compute@developer.gserviceaccount.com",
		ServiceAccountType:  "default-compute",
		ViolationType:       "default_compute_sa_editor",
		RiskLevel:           "medium",
		Description:         "Compute instance uses default service account with Editor permissions",
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
	})

	// Mark projects as processed
	g.projectsProcessed["test-project-123"] = "Test Project"

	slog.Info("Generated test violations", "iam_violations", len(g.violations), "instance_violations", len(g.instanceViolations))
}