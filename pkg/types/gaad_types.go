package types

type AuthorizationAccountDetails struct {
	AccountID       string                `json:"accountId"`
	UserDetailList  []UserDetail          `json:"UserDetailList"`
	GroupDetailList []GroupDetail         `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail          `json:"RoleDetailList"`
	Policies        []ManagedPolicyDetail `json:"Policies"`
}

type UserDetail struct {
	Arn                     string          `json:"Arn"`
	UserName                string          `json:"UserName"`
	UserId                  string          `json:"UserId"`
	Path                    string          `json:"Path"`
	CreateDate              string          `json:"CreateDate"`
	GroupList               []string        `json:"GroupList"`
	Tags                    []Tag           `json:"Tags"`
	UserPolicyList          []InlinePolicy  `json:"UserPolicyList"`
	PermissionsBoundary     ManagedPolicy   `json:"PermissionsBoundary"`
	AttachedManagedPolicies []ManagedPolicy `json:"AttachedManagedPolicies"`
}

type RoleDetail struct {
	Arn                      string            `json:"Arn"`
	RoleName                 string            `json:"RoleName"`
	RoleId                   string            `json:"RoleId"`
	Path                     string            `json:"Path"`
	CreateDate               string            `json:"CreateDate"`
	RoleLastUsed             map[string]string `json:"RoleLastUsed"`
	AssumeRolePolicyDocument Policy            `json:"AssumeRolePolicyDocument"`
	Tags                     []Tag             `json:"Tags"`
	RolePolicyList           []InlinePolicy    `json:"RolePolicyList"`
	AttachedManagedPolicies  []ManagedPolicy   `json:"AttachedManagedPolicies"`
	PermissionsBoundary      ManagedPolicy     `json:"PermissionsBoundary"`
	InstanceProfileList      []InstanceProfile `json:"InstanceProfileList"`
}

type GroupDetail struct {
	Path                    string          `json:"Path"`
	GroupName               string          `json:"GroupName"`
	GroupId                 string          `json:"GroupId"`
	Arn                     string          `json:"Arn"`
	CreateDate              string          `json:"CreateDate"`
	GroupPolicyList         []InlinePolicy  `json:"GroupPolicyList"`
	AttachedManagedPolicies []ManagedPolicy `json:"AttachedManagedPolicies"`
}

type ManagedPolicyDetail struct {
	PolicyName                    string          `json:"PolicyName"`
	PolicyId                      string          `json:"PolicyId"`
	Arn                           string          `json:"Arn"`
	Path                          string          `json:"Path"`
	DefaultVersionId              string          `json:"DefaultVersionId"`
	AttachmentCount               int             `json:"AttachmentCount"`
	PermissionsBoundaryUsageCount int             `json:"PermissionsBoundaryUsageCount"`
	IsAttachable                  bool            `json:"IsAttachable"`
	CreateDate                    string          `json:"CreateDate"`
	UpdateDate                    string          `json:"UpdateDate"`
	PolicyVersionList             []PolicyVersion `json:"PolicyVersionList"`
}

// DefaultPolicyDocument retrieves the default policy version document
func (policy *ManagedPolicyDetail) DefaultPolicyDocument() *Policy {
	for _, version := range policy.PolicyVersionList {
		if version.IsDefaultVersion {
			return &version.Document
		}
	}
	return nil
}
