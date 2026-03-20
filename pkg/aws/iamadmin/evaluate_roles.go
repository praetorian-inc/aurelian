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

func (e *Evaluator) evaluateRole(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.isRoleAdmin(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate role %s: %w", resource.ResourceID, err)
	}
	if !isAdmin {
		return nil
	}

	resource.IsAdmin = &isAdmin
	out.Send(resource)
	return nil
}

func (e *Evaluator) isRoleAdmin(ctx context.Context, roleName string) (bool, error) {
	attachedPolicies, err := e.listAttachedRolePolicies(ctx, roleName)
	if err != nil {
		return false, fmt.Errorf("evaluate role %s attached policies: %w", roleName, err)
	}
	if hasAdministratorAccessPolicy(attachedPolicies) {
		return true, nil
	}

	hasAdminInlinePolicy, err := e.roleHasAdminInlinePolicy(ctx, roleName)
	if err != nil {
		return false, fmt.Errorf("evaluate role %s inline policies: %w", roleName, err)
	}

	return hasAdminInlinePolicy, nil
}

func (e *Evaluator) listAttachedRolePolicies(ctx context.Context, roleName string) ([]iamtypes.AttachedPolicy, error) {
	policies := make([]iamtypes.AttachedPolicy, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName), Marker: marker})
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

func (e *Evaluator) roleHasAdminInlinePolicy(ctx context.Context, roleName string) (bool, error) {
	policyNames, err := e.listRolePolicyNames(ctx, roleName)
	if err != nil {
		return false, err
	}

	for _, policyName := range policyNames {
		policy, getErr := e.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(roleName), PolicyName: aws.String(policyName)})
		if getErr != nil {
			return false, getErr
		}
		if policyDocumentHasAdminWildcardStatement(aws.ToString(policy.PolicyDocument)) {
			return true, nil
		}
	}

	return false, nil
}

func (e *Evaluator) listRolePolicyNames(ctx context.Context, roleName string) ([]string, error) {
	policyNames := make([]string, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName), Marker: marker})
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
