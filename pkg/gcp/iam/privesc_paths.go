package iam

import (
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// PrivescPath defines a GCP privilege escalation path.
type PrivescPath struct {
	Name        string
	Permissions []string
	Description string
	Severity    output.RiskSeverity
	Remediation string
	References  []string
}

// PrivescPaths enumerates known GCP privilege escalation paths based on
// Rhino Security Labs research.
var PrivescPaths = []PrivescPath{
	{
		Name:        "gcp-privesc-sa-key-create",
		Permissions: []string{"iam.serviceAccountKeys.create"},
		Description: "Can create service account keys, granting persistent access as any service account.",
		Severity:    output.RiskSeverityCritical,
		Remediation: "Remove iam.serviceAccountKeys.create permission. Use Workload Identity Federation instead of SA keys.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-sa-set-iam-policy",
		Permissions: []string{"iam.serviceAccounts.setIamPolicy"},
		Description: "Can modify IAM policy on service accounts, granting ability to impersonate any SA.",
		Severity:    output.RiskSeverityCritical,
		Remediation: "Remove iam.serviceAccounts.setIamPolicy permission. Use least-privilege IAM bindings.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-sa-get-access-token",
		Permissions: []string{"iam.serviceAccounts.getAccessToken"},
		Description: "Can generate access tokens for service accounts, enabling direct impersonation.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Remove iam.serviceAccounts.getAccessToken. Restrict service account token creation.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-sa-implicit-delegation",
		Permissions: []string{"iam.serviceAccounts.implicitDelegation"},
		Description: "Can impersonate service accounts through delegation chains.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Remove iam.serviceAccounts.implicitDelegation. Audit delegation chains.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-deploymentmanager",
		Permissions: []string{"iam.serviceAccounts.actAs", "deploymentmanager.deployments.create"},
		Description: "Can deploy resources as a service account via Deployment Manager, escalating to that SA's permissions.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict deploymentmanager.deployments.create and iam.serviceAccounts.actAs to trusted principals only.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-cloudfunctions",
		Permissions: []string{"iam.serviceAccounts.actAs", "cloudfunctions.functions.create"},
		Description: "Can create Cloud Functions running as a service account, executing arbitrary code with that SA's permissions.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict cloudfunctions.functions.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-compute-instances",
		Permissions: []string{"iam.serviceAccounts.actAs", "compute.instances.create"},
		Description: "Can create Compute Engine instances running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict compute.instances.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-cloud-run",
		Permissions: []string{"iam.serviceAccounts.actAs", "run.services.create"},
		Description: "Can create Cloud Run services running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict run.services.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-orgpolicy-set",
		Permissions: []string{"orgpolicy.policy.set"},
		Description: "Can modify organization policies, potentially disabling security constraints.",
		Severity:    output.RiskSeverityCritical,
		Remediation: "Remove orgpolicy.policy.set from non-admin principals. Use organization policy administrator role sparingly.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-project-set-iam-policy",
		Permissions: []string{"resourcemanager.projects.setIamPolicy"},
		Description: "Can modify project-level IAM policy, granting any role to any principal.",
		Severity:    output.RiskSeverityCritical,
		Remediation: "Remove resourcemanager.projects.setIamPolicy. Use more granular IAM permissions.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-hmac-keys",
		Permissions: []string{"storage.hmacKeys.create"},
		Description: "Can create HMAC keys for service accounts, providing persistent storage access.",
		Severity:    output.RiskSeverityMedium,
		Remediation: "Remove storage.hmacKeys.create. Monitor HMAC key creation via audit logs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-api-keys-create",
		Permissions: []string{"serviceusage.apiKeys.create"},
		Description: "Can create API keys that may bypass API restrictions.",
		Severity:    output.RiskSeverityMedium,
		Remediation: "Remove serviceusage.apiKeys.create. Use service accounts instead of API keys.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
	{
		Name:        "gcp-privesc-cloudbuild",
		Permissions: []string{"iam.serviceAccounts.actAs", "cloudbuild.builds.create"},
		Description: "Can create Cloud Build jobs running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict cloudbuild.builds.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/"},
	},
	{
		Name:        "gcp-privesc-composer",
		Permissions: []string{"iam.serviceAccounts.actAs", "composer.environments.create"},
		Description: "Can create Cloud Composer environments running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict composer.environments.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/"},
	},
	{
		Name:        "gcp-privesc-dataflow",
		Permissions: []string{"iam.serviceAccounts.actAs", "dataflow.jobs.create"},
		Description: "Can create Dataflow jobs running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict dataflow.jobs.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/"},
	},
	{
		Name:        "gcp-privesc-dataproc",
		Permissions: []string{"iam.serviceAccounts.actAs", "dataproc.clusters.create"},
		Description: "Can create Dataproc clusters running as a service account.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Restrict dataproc.clusters.create and iam.serviceAccounts.actAs.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/"},
	},
	{
		Name:        "gcp-privesc-custom-role-update",
		Permissions: []string{"iam.roles.update"},
		Description: "Can update custom IAM roles to add arbitrary permissions.",
		Severity:    output.RiskSeverityHigh,
		Remediation: "Remove iam.roles.update. Use predefined roles where possible.",
		References:  []string{"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"},
	},
}

// AllPrivescPermissions returns a deduplicated list of all permissions needed
// across all privilege escalation paths.
func AllPrivescPermissions() []string {
	seen := make(map[string]struct{})
	var perms []string
	for _, p := range PrivescPaths {
		for _, perm := range p.Permissions {
			if _, ok := seen[perm]; !ok {
				seen[perm] = struct{}{}
				perms = append(perms, perm)
			}
		}
	}
	return perms
}

// MatchPaths returns which privilege escalation paths are satisfied by the
// given set of granted permissions.
func MatchPaths(grantedPermissions []string) []PrivescPath {
	var matched []PrivescPath
	for _, path := range PrivescPaths {
		if allPresent(path.Permissions, grantedPermissions) {
			matched = append(matched, path)
		}
	}
	return matched
}

// allPresent returns true if every element of required is in granted.
func allPresent(required, granted []string) bool {
	for _, r := range required {
		if !slices.Contains(granted, r) {
			return false
		}
	}
	return true
}
