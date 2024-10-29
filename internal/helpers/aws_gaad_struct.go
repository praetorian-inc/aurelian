package helpers

type Gaad struct {
	UserDetailList  []UserDL     `json:"UserDetailList"`
	RoleDetailList  []RoleDL     `json:"RoleDetailList"`
	GroupDetailList []GroupDL    `json:"GroupDetailList"`
	Policies        []PoliciesDL `json:"Policies"`
}

type PrincipalPL struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument Policy `json:"PolicyDocument"`
}

type ManagedPL struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type UserDL struct {
	Arn                     string        `json:"Arn"`
	UserName                string        `json:"UserName"`
	UserId                  string        `json:"UserId"`
	Path                    string        `json:"Path"`
	CreateDate              string        `json:"CreateDate"`
	GroupList               []string      `json:"GroupList"`
	Tags                    []Tag         `json:"Tags"`
	UserPolicyList          []PrincipalPL `json:"UserPolicyList"`
	AttachedManagedPolicies []ManagedPL   `json:"AttachedManagedPolicies"`
}

type InstanceProfile struct {
	Path                string                `json:"Path"`
	InstanceProfileName string                `json:"InstanceProfileName"`
	InstanceProfileId   string                `json:"InstanceProfileId"`
	Arn                 string                `json:"Arn"`
	CreateDate          string                `json:"CreateDate"`
	Roles               []InstanceProfileRole `json:"Roles"`
}

type InstanceProfileRole struct {
	Path                     string `json:"Path"`
	RoleName                 string `json:"RoleName"`
	RoleId                   string `json:"RoleId"`
	Arn                      string `json:"Arn"`
	CreateDate               string `json:"CreateDate"`
	AssumeRolePolicyDocument Policy `json:"AssumeRolePolicyDocument"`
}

type RoleDL struct {
	Arn                      string            `json:"Arn"`
	RoleName                 string            `json:"RoleName"`
	RoleId                   string            `json:"RoleId"`
	Path                     string            `json:"Path"`
	CreateDate               string            `json:"CreateDate"`
	RoleLastUsed             map[string]string `json:"RoleLastUsed"`
	AssumeRolePolicyDocument Policy            `json:"AssumeRolePolicyDocument"`
	Tags                     []Tag             `json:"Tags"`
	RolePolicyList           []PrincipalPL     `json:"RolePolicyList"`
	AttachedManagedPolicies  []ManagedPL       `json:"AttachedManagedPolicies"`
	InstanceProfileList      []InstanceProfile `json:"InstanceProfileList"`
}

type GroupDL struct {
	Path                    string        `json:"Path"`
	GroupName               string        `json:"GroupName"`
	GroupId                 string        `json:"GroupId"`
	Arn                     string        `json:"Arn"`
	CreateDate              string        `json:"CreateDate"`
	GroupPolicyList         []PrincipalPL `json:"GroupPolicyList"`
	AttachedManagedPolicies []ManagedPL   `json:"AttachedManagedPolicies"`
}

type PoliciesDL struct {
	PolicyName                    string       `json:"PolicyName"`
	PolicyId                      string       `json:"PolicyId"`
	Arn                           string       `json:"Arn"`
	Path                          string       `json:"Path"`
	DefaultVersionId              string       `json:"DefaultVersionId"`
	AttachmentCount               int          `json:"AttachmentCount"`
	PermissionsBoundaryUsageCount int          `json:"PermissionsBoundaryUsageCount"`
	IsAttachable                  bool         `json:"IsAttachable"`
	CreateDate                    string       `json:"CreateDate"`
	UpdateDate                    string       `json:"UpdateDate"`
	PolicyVersionList             []PoliciesVL `json:"PolicyVersionList"`
}

type PoliciesVL struct {
	VersionId        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
	CreateDate       string `json:"CreateDate"`
	Document         Policy `json:"Document"`
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}
