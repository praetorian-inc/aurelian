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
	registry.Register("gcp", "recon", GcpDefaultServiceAccounts.Metadata().Properties()["id"].(string), *GcpDefaultServiceAccounts)
}

var GcpDefaultServiceAccounts = chain.NewModule(
	cfg.NewMetadata(
		"GCP Default Service Account Detection",
		"Detect default service accounts with excessive permissions across a GCP organization that should be replaced with custom service accounts following least privilege principles.",
	).WithProperties(map[string]any{
		"id":          "default-service-accounts",
		"platform":    "gcp",
		"category":    "recon",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://cloud.google.com/iam/docs/service-accounts#default",
			"https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_default_grants",
			"https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
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
This module identifies default service accounts in GCP organizations that pose security risks due to their broad permissions:

**Detected Service Account Types:**
- **Compute Engine Default Service Account**: Projects create default service accounts with Editor role for Compute Engine instances
- **App Engine Default Service Account**: App Engine applications use default service accounts with broad permissions
- **Other Default Service Accounts**: Various GCP services create default service accounts with excessive privileges

**Security Risks:**
Default service accounts are created automatically by GCP services and often granted overly broad permissions like the Editor role. These accounts violate the principle of least privilege and should be replaced with custom service accounts that have only the minimum permissions required for their specific function.

**Detection Method:**
1. Enumerates all projects in the specified GCP organization
2. Lists all service accounts in each accessible project
3. Identifies service accounts matching default patterns (e.g., *-compute@developer.gserviceaccount.com)
4. Reports violations with service account details, associated projects, and risk assessment

**Remediation:**
Replace default service accounts with custom service accounts that have:
- Specific, minimal IAM roles instead of broad roles like Editor
- Custom names that reflect their purpose
- Regular access reviews and rotation schedules

The module provides detailed findings including CVSS scoring and specific remediation guidance for each violation.
`,
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithStrictness(chain.Lax).WithLinks(
	// Phase 1: Organization and project discovery
	hierarchy.NewGcpOrgInfoLink,
	hierarchy.NewGcpOrgProjectListLink,

	// Phase 2: IAM policy collection (needed for service account analysis)
	iam.NewGcpProjectIamPolicyLink,

	// Phase 3: Default service account analysis
	iam.NewGcpDefaultServiceAccountAnalyzer,
).WithOutputters(
	outputters.NewSecurityFindingsJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[bool]("include-sys-projects", "include system projects from analysis").WithDefault(true),
).WithConfigs(
	cfg.WithArg("module-name", "default-service-accounts"),
	cfg.WithArg("include-sys-projects", true),
)
