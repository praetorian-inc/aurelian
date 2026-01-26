package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/iam"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpPrimitiveRoles.Metadata().Properties()["id"].(string), *GcpPrimitiveRoles)
}

var GcpPrimitiveRoles = chain.NewModule(
	cfg.NewMetadata(
		"GCP Primitive IAM Roles Detection",
		"Detect principals using primitive/basic IAM roles (Owner, Editor, Viewer) across a GCP organization that violate the principle of least privilege.",
	).WithProperties(map[string]any{
		"id":          "primitive-roles",
		"platform":    "gcp",
		"category":    "recon",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://cloud.google.com/iam/docs/understanding-roles#basic",
			"https://cloud.google.com/iam/docs/using-iam-securely#least_privilege",
		},
		"tactics": []string{
			"Privilege Escalation",
			"Persistence",
		},
		"techniques": []string{
			"T1078.004", // Valid Accounts: Cloud Accounts
			"T1068",     // Exploitation for Privilege Escalation
		},
		"description": `
This module identifies principals in GCP organizations that are assigned primitive/basic IAM roles that violate the principle of least privilege:

**Detected Violations:**
- **roles/owner**: Full administrative access to the project and all resources
- **roles/editor**: Edit access to all resources in the project
- **roles/viewer**: Read-only access to all resources in the project

**Security Impact:**
Primitive roles grant broad permissions across an entire project rather than following least-privilege principles. These roles should be replaced with more specific, granular roles that provide only the minimum permissions necessary for the principal's function.

**Detection Method:**
1. Enumerates all projects in the specified GCP organization
2. Extracts IAM policies from each accessible project
3. Identifies all principals (users, service accounts, groups) assigned primitive roles
4. Reports violations with principal details, role assignments, and risk assessment

The module provides detailed findings including CVSS scoring and remediation guidance for each violation.
`,
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithStrictness(chain.Lax).WithLinks(
	// Phase 1: Organization and project discovery
	hierarchy.NewGcpOrgInfoLink,
	hierarchy.NewGcpOrgProjectListLink,

	// Phase 2: IAM policy collection
	iam.NewGcpProjectIamPolicyLink,

	// Phase 3: Primitive roles security analysis
	iam.NewGcpPrimitiveRolesAnalyzer,
).WithOutputters(
	outputters.NewSecurityFindingsJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[bool]("include-sys-projects", "include system projects from analysis").WithDefault(true),
	cfg.NewParam[bool]("exclude-default-service-accounts", "exclude default service accounts from primitive role detection").WithDefault(false),
).WithConfigs(
	cfg.WithArg("module-name", "primitive-roles"),
	cfg.WithArg("include-sys-projects", true),
	cfg.WithArg("exclude-default-service-accounts", false),
)
