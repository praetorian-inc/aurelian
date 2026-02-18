package iam

import "github.com/praetorian-inc/aurelian/pkg/types"

type Gaad struct {
	UserDetailList  []UserDL     `json:"UserDetailList"`
	RoleDetailList  []RoleDL     `json:"RoleDetailList"`
	GroupDetailList []GroupDL    `json:"GroupDetailList"`
	Policies        []PoliciesDL `json:"Policies"`
}

// PrincipalPL is an alias for types.PrincipalPL, kept here for backward compatibility.
type PrincipalPL = types.PrincipalPL

// ManagedPL is an alias for types.ManagedPL, kept here for backward compatibility.
type ManagedPL = types.ManagedPL

type UserDL struct {
	Arn                     string        `json:"Arn"`
	UserName                string        `json:"UserName"`
	UserId                  string        `json:"UserId"`
	Path                    string        `json:"Path"`
	CreateDate              string        `json:"CreateDate"`
	GroupList               []string      `json:"GroupList"`
	Tags                    []Tag         `json:"Tags"`
	UserPolicyList          []PrincipalPL `json:"UserPolicyList"`
	PermissionsBoundary     ManagedPL     `json:"PermissionsBoundary"`
	AttachedManagedPolicies []ManagedPL   `json:"AttachedManagedPolicies"`
}

// InstanceProfile is an alias for types.InstanceProfile, kept here for backward compatibility.
type InstanceProfile = types.InstanceProfile

// InstanceProfileRole is an alias for types.InstanceProfileRole, kept here for backward compatibility.
type InstanceProfileRole = types.InstanceProfileRole

type RoleDL struct {
	Arn                      string            `json:"Arn"`
	RoleName                 string            `json:"RoleName"`
	RoleId                   string            `json:"RoleId"`
	Path                     string            `json:"Path"`
	CreateDate               string            `json:"CreateDate"`
	RoleLastUsed             map[string]string `json:"RoleLastUsed"`
	AssumeRolePolicyDocument types.Policy      `json:"AssumeRolePolicyDocument"`
	Tags                     []Tag             `json:"Tags"`
	RolePolicyList           []PrincipalPL     `json:"RolePolicyList"`
	AttachedManagedPolicies  []ManagedPL       `json:"AttachedManagedPolicies"`
	PermissionsBoundary      ManagedPL         `json:"PermissionsBoundary"`
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

// DefaultPolicyDocument retrieves the default policy version document
func (policy *PoliciesDL) DefaultPolicyDocument() *types.Policy {
	for _, version := range policy.PolicyVersionList {
		if version.IsDefaultVersion {
			return &version.Document
		}
	}
	return nil
}

// PoliciesVL is an alias for types.PoliciesVL, kept here for backward compatibility.
type PoliciesVL = types.PoliciesVL

// Tag is an alias for types.Tag, kept here for backward compatibility.
type Tag = types.Tag
