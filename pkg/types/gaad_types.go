package types

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/store"
)

type AuthorizationAccountDetails struct {
	model.BaseAurelianModel
	AccountID string                         `json:"-"`
	Users     store.Map[UserDetail]          `json:"-"`
	Groups    store.Map[GroupDetail]         `json:"-"`
	Roles     store.Map[RoleDetail]          `json:"-"`
	Policies  store.Map[ManagedPolicyDetail] `json:"-"`
}

// NewAuthorizationAccountDetails constructs an AuthorizationAccountDetails from
// slices, populating the cache maps keyed by ARN. Useful in tests and when
// converting from legacy slice-based representations.
func NewAuthorizationAccountDetails(
	accountID string,
	users []UserDetail,
	groups []GroupDetail,
	roles []RoleDetail,
	policies []ManagedPolicyDetail,
) *AuthorizationAccountDetails {
	a := &AuthorizationAccountDetails{
		AccountID: accountID,
		Users:     store.NewMap[UserDetail](),
		Groups:    store.NewMap[GroupDetail](),
		Roles:     store.NewMap[RoleDetail](),
		Policies:  store.NewMap[ManagedPolicyDetail](),
	}
	for _, u := range users {
		a.Users.Set(u.Arn, u)
	}
	for _, g := range groups {
		a.Groups.Set(g.Arn, g)
	}
	for _, r := range roles {
		a.Roles.Set(r.Arn, r)
	}
	for _, p := range policies {
		a.Policies.Set(p.Arn, p)
	}
	return a
}

// gaadJSON is the wire-format representation, preserving the original JSON schema.
type gaadJSON struct {
	AccountID       string                `json:"accountId"`
	UserDetailList  []UserDetail          `json:"UserDetailList"`
	GroupDetailList []GroupDetail         `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail          `json:"RoleDetailList"`
	Policies        []ManagedPolicyDetail `json:"Policies"`
}

func (a *AuthorizationAccountDetails) MarshalJSON() ([]byte, error) {
	wire := gaadJSON{AccountID: a.AccountID}

	a.Users.Range(func(_ string, v UserDetail) bool {
		wire.UserDetailList = append(wire.UserDetailList, v)
		return true
	})
	a.Groups.Range(func(_ string, v GroupDetail) bool {
		wire.GroupDetailList = append(wire.GroupDetailList, v)
		return true
	})
	a.Roles.Range(func(_ string, v RoleDetail) bool {
		wire.RoleDetailList = append(wire.RoleDetailList, v)
		return true
	})
	a.Policies.Range(func(_ string, v ManagedPolicyDetail) bool {
		wire.Policies = append(wire.Policies, v)
		return true
	})

	return json.Marshal(wire)
}

func (a *AuthorizationAccountDetails) UnmarshalJSON(data []byte) error {
	var wire gaadJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	a.AccountID = wire.AccountID
	a.Users = store.NewMap[UserDetail]()
	a.Groups = store.NewMap[GroupDetail]()
	a.Roles = store.NewMap[RoleDetail]()
	a.Policies = store.NewMap[ManagedPolicyDetail]()

	for _, u := range wire.UserDetailList {
		a.Users.Set(u.Arn, u)
	}
	for _, g := range wire.GroupDetailList {
		a.Groups.Set(g.Arn, g)
	}
	for _, r := range wire.RoleDetailList {
		a.Roles.Set(r.Arn, r)
	}
	for _, p := range wire.Policies {
		a.Policies.Set(p.Arn, p)
	}

	return nil
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

	// AccessKeyCount is the number of ACTIVE access keys on the user, collected
	// out-of-band via iam:ListAccessKeys (GAAD does not return access keys). AWS
	// caps a user at 2 active keys, so privesc methods use this to know whether
	// iam:CreateAccessKey would succeed. Tri-state pointer: nil = unknown (the
	// ListAccessKeys call was not made or failed) and serializes to null, which
	// flattenStruct drops so the node prop is ABSENT and downstream guards
	// fail-open; a non-nil 0/1/2+ serializes the real count present on the node so
	// the guard reads it. A plain int + omitempty would drop a confirmed 0,
	// re-introducing the absent/fail-open ambiguity.
	AccessKeyCount *int `json:"AccessKeyCount,omitempty"`
	// HasLoginProfile records whether the user has a console login profile,
	// collected out-of-band via iam:GetLoginProfile. Tri-state pointer: nil =
	// unknown (call not made or failed other than NoSuchEntity) and serializes to
	// null → dropped → absent → fail-open; non-nil false = confirmed NoSuchEntity
	// (no profile) and serializes present so the guard suppresses; non-nil true =
	// profile exists. A plain bool + omitempty would drop a confirmed false,
	// making the node carry no prop and the guard's coalesce(...,true) always
	// fire — defeating the suppression.
	HasLoginProfile *bool `json:"HasLoginProfile,omitempty"`
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
