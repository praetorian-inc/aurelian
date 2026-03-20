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

func (e *Evaluator) evaluateUser(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.isUserAdmin(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate user %s: %w", resource.ResourceID, err)
	}
	if !isAdmin {
		return nil
	}

	resource.IsAdmin = true
	out.Send(resource)
	e.emittedUsers[resource.ResourceID] = true
	return nil
}

func (e *Evaluator) isUserAdmin(ctx context.Context, userName string) (bool, error) {
	attachedPolicies, err := e.listAttachedUserPolicies(ctx, userName)
	if err != nil {
		return false, fmt.Errorf("evaluate user %s attached policies: %w", userName, err)
	}
	if hasAdministratorAccessPolicy(attachedPolicies) {
		return true, nil
	}

	hasAdminInlinePolicy, err := e.userHasAdminInlinePolicy(ctx, userName)
	if err != nil {
		return false, fmt.Errorf("evaluate user %s inline policies: %w", userName, err)
	}

	return hasAdminInlinePolicy, nil
}

func (e *Evaluator) listAttachedUserPolicies(ctx context.Context, userName string) ([]iamtypes.AttachedPolicy, error) {
	policies := make([]iamtypes.AttachedPolicy, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(userName), Marker: marker})
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

func (e *Evaluator) userHasAdminInlinePolicy(ctx context.Context, userName string) (bool, error) {
	policyNames, err := e.listUserPolicyNames(ctx, userName)
	if err != nil {
		return false, err
	}

	for _, policyName := range policyNames {
		policy, getErr := e.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(userName), PolicyName: aws.String(policyName)})
		if getErr != nil {
			return false, getErr
		}
		if policyDocumentHasAdminWildcardStatement(aws.ToString(policy.PolicyDocument)) {
			return true, nil
		}
	}

	return false, nil
}

func (e *Evaluator) listUserPolicyNames(ctx context.Context, userName string) ([]string, error) {
	policyNames := make([]string, 0)
	var marker *string
	paginator := ratelimit.NewAWSPaginator()

	err := paginator.Paginate(func() (bool, error) {
		result, err := e.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(userName), Marker: marker})
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
