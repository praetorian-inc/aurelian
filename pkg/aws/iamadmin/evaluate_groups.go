package iamadmin

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func (e *Evaluator) evaluateGroup(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.isGroupAdmin(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate group %s: %w", resource.ResourceID, err)
	}
	if !isAdmin {
		return nil
	}

	resource.IsAdmin = true
	out.Send(resource)

	members, err := e.getGroupMembers(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate group %s members: %w", resource.ResourceID, err)
	}

	for _, member := range members {
		if e.emittedUsers[member] {
			continue
		}

		out.Send(output.AWSResource{
			ResourceType: "AWS::IAM::User",
			ResourceID:   member,
			AccountRef:   resource.AccountRef,
			Region:       "global",
			DisplayName:  fmt.Sprintf("%s (via group %s)", member, resource.ResourceID),
			IsAdmin:      true,
		})
		e.emittedUsers[member] = true
	}

	return nil
}

func (e *Evaluator) isGroupAdmin(ctx context.Context, groupName string) (bool, error) {
	attachedPolicies, err := e.listAttachedGroupPolicies(ctx, groupName)
	if err != nil {
		return false, fmt.Errorf("evaluate group %s attached policies: %w", groupName, err)
	}
	if hasAdministratorAccessPolicy(attachedPolicies) {
		return true, nil
	}

	hasAdminInlinePolicy, err := e.groupHasAdminInlinePolicy(ctx, groupName)
	if err != nil {
		return false, fmt.Errorf("evaluate group %s inline policies: %w", groupName, err)
	}

	return hasAdminInlinePolicy, nil
}

func (e *Evaluator) getGroupMembers(ctx context.Context, groupName string) ([]string, error) {
	members := make([]string, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.GetGroup(ctx, &iam.GetGroupInput{GroupName: aws.String(groupName), Marker: marker})
		if err != nil {
			return false, fmt.Errorf("get group members for %s: %w", groupName, err)
		}

		for _, user := range result.Users {
			members = append(members, aws.ToString(user.UserName))
		}

		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return members, nil
}

func (e *Evaluator) listAttachedGroupPolicies(ctx context.Context, groupName string) ([]iamtypes.AttachedPolicy, error) {
	policies := make([]iamtypes.AttachedPolicy, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(groupName), Marker: marker})
		if err != nil {
			return false, err
		}

		policies = append(policies, result.AttachedPolicies...)
		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})

	return policies, err
}

func (e *Evaluator) groupHasAdminInlinePolicy(ctx context.Context, groupName string) (bool, error) {
	policyNames, err := e.listGroupPolicyNames(ctx, groupName)
	if err != nil {
		return false, err
	}

	for _, policyName := range policyNames {
		policy, getErr := e.iam.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: aws.String(groupName), PolicyName: aws.String(policyName)})
		if getErr != nil {
			return false, getErr
		}
		if policyDocumentHasAdminWildcardStatement(aws.ToString(policy.PolicyDocument)) {
			return true, nil
		}
	}

	return false, nil
}

func (e *Evaluator) listGroupPolicyNames(ctx context.Context, groupName string) ([]string, error) {
	policyNames := make([]string, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: aws.String(groupName), Marker: marker})
		if err != nil {
			return false, err
		}

		policyNames = append(policyNames, result.PolicyNames...)
		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})

	return policyNames, err
}
