package output

// ResourceRef identifies a resource without Neo4j key knowledge.
// This is pure domain data - Chariot generates keys from this.
type ResourceRef struct {
	Platform string `json:"platform"` // "aws", "azure", "gcp"
	Type     string `json:"type"`     // "iam-user", "s3-bucket", etc.
	ID       string `json:"id"`       // ARN or resource path
	Account  string `json:"account"`  // Account/subscription/project
}

// IAMPermission represents an IAM permission - pure domain data
// NO Neo4j key knowledge - Chariot generates keys
type IAMPermission struct {
	Source     ResourceRef    `json:"source"`
	Target     ResourceRef    `json:"target"`
	Permission string         `json:"permission"`              // "s3:GetObject"
	Effect     string         `json:"effect,omitempty"`        // "Allow" or "Deny"
	Conditions map[string]any `json:"conditions,omitempty"`    // IAM policy conditions
	Capability string         `json:"capability"`              // Scanner identifier
	Timestamp  string         `json:"timestamp"`               // ISO 8601 format
}

// SSMPermission extends IAMPermission with SSM-specific fields
type SSMPermission struct {
	IAMPermission
	SSMDocumentRestrictions []string `json:"ssm_document_restrictions,omitempty"`
	AllowsShellExecution    bool     `json:"allows_shell_execution"`
}

// GitHubActionsPermission for OIDC federation
type GitHubActionsPermission struct {
	IAMPermission
	SubjectPatterns []string `json:"subject_patterns,omitempty"`
	RepositoryOrg   string   `json:"repository_org,omitempty"`
	RepositoryName  string   `json:"repository_name,omitempty"`
}

// Repository represents a source code repository
type Repository struct {
	Platform string `json:"platform"` // "github", "gitlab"
	Org      string `json:"org"`
	Name     string `json:"name"`
	URL      string `json:"url"`
}

// ServicePrincipal represents an AWS service principal
type ServicePrincipal struct {
	Service  string `json:"service"`   // "lambda.amazonaws.com"
	FullName string `json:"full_name"` // Full principal string
}
