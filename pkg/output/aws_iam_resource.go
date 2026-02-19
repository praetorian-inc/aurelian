package output

import "github.com/praetorian-inc/aurelian/pkg/types"

// AWSIAMResource wraps AWSResource with typed IAM fields.
// For non-IAM resources, all IAM-specific fields are nil/empty.
// This is an output-boundary type — internal analyzer types remain unchanged.
type AWSIAMResource struct {
	AWSResource

	// IAM-specific typed fields (nil/empty for non-IAM resources)
	InlinePolicies          []types.PrincipalPL    `json:"inline_policies,omitempty"`
	AttachedManagedPolicies []types.ManagedPL      `json:"attached_managed_policies,omitempty"`
	PermissionsBoundary     *types.ManagedPL       `json:"permissions_boundary,omitempty"`
	AssumeRolePolicy        *types.Policy          `json:"assume_role_policy,omitempty"`
	InstanceProfiles        []types.InstanceProfile `json:"instance_profiles,omitempty"`
	PolicyVersions          []types.PoliciesVL     `json:"policy_versions,omitempty"`
	GroupMemberships        []string               `json:"group_memberships,omitempty"`
	IAMTags                 []types.Tag            `json:"iam_tags,omitempty"`

	// OriginalData holds the original GAAD struct (UserDL, RoleDL, etc.)
	// for lossless conversion back to graph nodes. Not serialized to JSON.
	OriginalData any `json:"-"`
}

// IsIAMResource returns true if this resource has IAM-specific fields populated.
func (r *AWSIAMResource) IsIAMResource() bool {
	return len(r.InlinePolicies) > 0 ||
		len(r.AttachedManagedPolicies) > 0 ||
		r.AssumeRolePolicy != nil ||
		len(r.InstanceProfiles) > 0 ||
		len(r.PolicyVersions) > 0 ||
		len(r.GroupMemberships) > 0
}

// FromAWSResource wraps a plain AWSResource as an AWSIAMResource with nil IAM fields.
func FromAWSResource(cr AWSResource) AWSIAMResource {
	return AWSIAMResource{AWSResource: cr}
}

