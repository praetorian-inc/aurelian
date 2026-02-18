package output

// AWSIAMResource wraps CloudResource with typed IAM fields.
// For non-IAM resources, all IAM-specific fields are nil/empty.
// This is an output-boundary type — internal analyzer types remain unchanged.
type AWSIAMResource struct {
	CloudResource

	// IAM-specific typed fields (nil/empty for non-IAM resources)
	InlinePolicies          any      `json:"inline_policies,omitempty"`
	AttachedManagedPolicies any      `json:"attached_managed_policies,omitempty"`
	PermissionsBoundary     any      `json:"permissions_boundary,omitempty"`
	AssumeRolePolicy        any      `json:"assume_role_policy,omitempty"`
	InstanceProfiles        any      `json:"instance_profiles,omitempty"`
	PolicyVersions          any      `json:"policy_versions,omitempty"`
	GroupMemberships        []string `json:"group_memberships,omitempty"`
	IAMTags                 any      `json:"iam_tags,omitempty"`

	// OriginalData holds the original GAAD struct (UserDL, RoleDL, etc.)
	// for lossless conversion back to graph nodes. Not serialized to JSON.
	OriginalData any `json:"-"`
}

// IsIAMResource returns true if this resource has IAM-specific fields populated.
func (r *AWSIAMResource) IsIAMResource() bool {
	return r.InlinePolicies != nil ||
		r.AttachedManagedPolicies != nil ||
		r.AssumeRolePolicy != nil ||
		r.InstanceProfiles != nil ||
		r.PolicyVersions != nil ||
		len(r.GroupMemberships) > 0
}

// FromCloudResource wraps a plain CloudResource as an AWSIAMResource with nil IAM fields.
func FromCloudResource(cr CloudResource) AWSIAMResource {
	return AWSIAMResource{CloudResource: cr}
}
