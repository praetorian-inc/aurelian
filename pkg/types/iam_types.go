package types

// PrincipalPL represents an inline policy attached to an IAM principal
// (user, role, or group) in a GAAD report.
type PrincipalPL struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument Policy `json:"PolicyDocument"`
}

// ManagedPL represents a managed policy attachment reference.
type ManagedPL struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
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

// PoliciesVL represents a policy version entry in a GAAD report.
type PoliciesVL struct {
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
