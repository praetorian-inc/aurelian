package gaad

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// IAM entity → output.AWSResource converters
// ---------------------------------------------------------------------------

func newAWSResourceFromRole(role types.RoleDetail) *output.AWSResource {
	a, _ := arn.Parse(role.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::Role",
		ResourceID:   role.Arn,
		ARN:          role.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  role.RoleName,
	}
}

func newAWSResourceFromUser(user types.UserDetail) *output.AWSResource {
	a, _ := arn.Parse(user.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::User",
		ResourceID:   user.Arn,
		ARN:          user.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  user.UserName,
	}
}

func newAWSResourceFromGroup(group types.GroupDetail) *output.AWSResource {
	a, _ := arn.Parse(group.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::Group",
		ResourceID:   group.Arn,
		ARN:          group.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  group.GroupName,
	}
}

func newAWSResourceFromPolicy(policy types.ManagedPolicyDetail) *output.AWSResource {
	a, _ := arn.Parse(policy.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::ManagedPolicy",
		ResourceID:   policy.Arn,
		ARN:          policy.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  policy.PolicyName,
	}
}

// extractResourceTags extracts tags from an AWSResource's Properties map.
// CloudControl resources store tags as Properties["Tags"] = []{Key:..., Value:...}.
// IAM resources created from GAAD have no Properties, so this returns empty.
func extractResourceTags(r *output.AWSResource) map[string]string {
	if r == nil || r.Properties == nil {
		return map[string]string{}
	}
	tags, ok := r.Properties["Tags"]
	if !ok {
		return map[string]string{}
	}
	tagList, ok := tags.([]any)
	if !ok {
		return map[string]string{}
	}
	result := make(map[string]string, len(tagList))
	for _, t := range tagList {
		tag, ok := t.(map[string]any)
		if !ok {
			continue
		}
		key, _ := tag["Key"].(string)
		value, _ := tag["Value"].(string)
		if key != "" {
			result[key] = value
		}
	}
	return result
}
