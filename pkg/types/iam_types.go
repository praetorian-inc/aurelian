package types

// InlinePolicy represents an inline policy attached to an IAM principal
// (user, role, or group) in a GAAD report.
type InlinePolicy struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument Policy `json:"PolicyDocument"`
}

// ManagedPolicy represents a managed policy attachment reference.
type ManagedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// PermissionsBoundary represents a permissions boundary attached to an IAM
// user or role. It acts as a ceiling on the effective permissions the entity
// can have, regardless of its identity-based policies.
type PermissionsBoundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
}

// InstanceProfile represents an IAM instance profile from a GAAD report.
type InstanceProfile struct {
	Path                string                `json:"Path"`
	InstanceProfileName string                `json:"InstanceProfileName"`
	InstanceProfileId   string                `json:"InstanceProfileId"`
	Arn                 string                `json:"Arn"`
	CreateDate          string                `json:"CreateDate"`
	Roles               []InstanceProfileRole `json:"Roles"`
}

// InstanceProfileRole represents a role associated with an instance profile.
type InstanceProfileRole struct {
	Path                     string `json:"Path"`
	RoleName                 string `json:"RoleName"`
	RoleId                   string `json:"RoleId"`
	Arn                      string `json:"Arn"`
	CreateDate               string `json:"CreateDate"`
	AssumeRolePolicyDocument Policy `json:"AssumeRolePolicyDocument"`
}

// PolicyVersion represents a policy version entry in a GAAD report.
type PolicyVersion struct {
	VersionId        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
	CreateDate       string `json:"CreateDate"`
	Document         Policy `json:"Document"`
}

// Tag represents an IAM resource tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}
