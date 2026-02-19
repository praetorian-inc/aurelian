package iam

import "github.com/praetorian-inc/aurelian/pkg/types"

type AuthorizationAccountDetails struct {
	UserDetailList  []UserDetail          `json:"UserDetailList"`
	GroupDetailList []GroupDetail         `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail          `json:"RoleDetailList"`
	Policies        []ManagedPolicyDetail `json:"Policies"`
}

type UserDetail struct {
	Arn                     string                `json:"Arn"`
	UserName                string                `json:"UserName"`
	UserId                  string                `json:"UserId"`
	Path                    string                `json:"Path"`
	CreateDate              string                `json:"CreateDate"`
	GroupList               []string              `json:"GroupList"`
	Tags                    []Tag                 `json:"Tags"`
	UserPolicyList          []types.InlinePolicy  `json:"UserPolicyList"`
	PermissionsBoundary     types.ManagedPolicy   `json:"PermissionsBoundary"`
	AttachedManagedPolicies []types.ManagedPolicy `json:"AttachedManagedPolicies"`
}

// InstanceProfile is an alias for types.InstanceProfile, kept here for backward compatibility.
type InstanceProfile = types.InstanceProfile

// InstanceProfileRole is an alias for types.InstanceProfileRole, kept here for backward compatibility.
type InstanceProfileRole = types.InstanceProfileRole

type RoleDetail struct {
	Arn                      string                `json:"Arn"`
	RoleName                 string                `json:"RoleName"`
	RoleId                   string                `json:"RoleId"`
	Path                     string                `json:"Path"`
	CreateDate               string                `json:"CreateDate"`
	RoleLastUsed             map[string]string     `json:"RoleLastUsed"`
	AssumeRolePolicyDocument types.Policy          `json:"AssumeRolePolicyDocument"`
	Tags                     []Tag                 `json:"Tags"`
	RolePolicyList           []types.InlinePolicy  `json:"RolePolicyList"`
	AttachedManagedPolicies  []types.ManagedPolicy `json:"AttachedManagedPolicies"`
	PermissionsBoundary      types.ManagedPolicy   `json:"PermissionsBoundary"`
	InstanceProfileList      []InstanceProfile     `json:"InstanceProfileList"`
}

type GroupDetail struct {
	Path                    string                `json:"Path"`
	GroupName               string                `json:"GroupName"`
	GroupId                 string                `json:"GroupId"`
	Arn                     string                `json:"Arn"`
	CreateDate              string                `json:"CreateDate"`
	GroupPolicyList         []types.InlinePolicy  `json:"GroupPolicyList"`
	AttachedManagedPolicies []types.ManagedPolicy `json:"AttachedManagedPolicies"`
}

type ManagedPolicyDetail struct {
	PolicyName                    string                `json:"PolicyName"`
	PolicyId                      string                `json:"PolicyId"`
	Arn                           string                `json:"Arn"`
	Path                          string                `json:"Path"`
	DefaultVersionId              string                `json:"DefaultVersionId"`
	AttachmentCount               int                   `json:"AttachmentCount"`
	PermissionsBoundaryUsageCount int                   `json:"PermissionsBoundaryUsageCount"`
	IsAttachable                  bool                  `json:"IsAttachable"`
	CreateDate                    string                `json:"CreateDate"`
	UpdateDate                    string                `json:"UpdateDate"`
	PolicyVersionList             []types.PolicyVersion `json:"PolicyVersionList"`
}

// DefaultPolicyDocument retrieves the default policy version document
func (policy *ManagedPolicyDetail) DefaultPolicyDocument() *types.Policy {
	for _, version := range policy.PolicyVersionList {
		if version.IsDefaultVersion {
			return &version.Document
		}
	}
	return nil
}

// Tag is an alias for types.Tag, kept here for backward compatibility.
type Tag = types.Tag
