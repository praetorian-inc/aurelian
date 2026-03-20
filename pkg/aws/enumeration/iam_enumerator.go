package enumeration

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// IAMEnumerator enumerates IAM resources (roles, policies, users) using the
// native IAM SDK. IAM resources are truly global, so each sub-enumerator
// fetches once per lifetime via sync.Once.
type IAMEnumerator struct {
	plugin.AWSCommonRecon
	provider  *AWSConfigProvider
	accountID string
}

// iamSubEnumerator implements ResourceEnumerator for a single IAM resource type.
// EnumerateAll is guarded by sync.Once — first call fetches, subsequent calls are no-ops.
type iamSubEnumerator struct {
	resourceType string
	once         sync.Once
	onceErr      error
	parent       *IAMEnumerator
	listFn       func(out *pipeline.P[output.AWSResource]) error
	getByARNFn   func(arn string, out *pipeline.P[output.AWSResource]) error
}

func (s *iamSubEnumerator) ResourceType() string { return s.resourceType }

func (s *iamSubEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	s.once.Do(func() {
		s.onceErr = s.listFn(out)
	})
	return s.onceErr
}

func (s *iamSubEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	return s.getByARNFn(arn, out)
}

// NewIAMEnumerator creates an IAMEnumerator.
func NewIAMEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *IAMEnumerator {
	return &IAMEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

// RoleEnumerator returns a ResourceEnumerator for AWS::IAM::Role.
func (e *IAMEnumerator) RoleEnumerator() ResourceEnumerator {
	return &iamSubEnumerator{
		resourceType: "AWS::IAM::Role",
		parent:       e,
		listFn:       e.listRoles,
		getByARNFn:   e.getRoleByARN,
	}
}

// PolicyEnumerator returns a ResourceEnumerator for AWS::IAM::Policy.
func (e *IAMEnumerator) PolicyEnumerator() ResourceEnumerator {
	return &iamSubEnumerator{
		resourceType: "AWS::IAM::Policy",
		parent:       e,
		listFn:       e.listPolicies,
		getByARNFn:   e.getPolicyByARN,
	}
}

// UserEnumerator returns a ResourceEnumerator for AWS::IAM::User.
func (e *IAMEnumerator) UserEnumerator() ResourceEnumerator {
	return &iamSubEnumerator{
		resourceType: "AWS::IAM::User",
		parent:       e,
		listFn:       e.listUsers,
		getByARNFn:   e.getUserByARN,
	}
}

func (e *IAMEnumerator) resolveAccountID() error {
	if e.accountID != "" {
		return nil
	}
	if e.provider == nil {
		return fmt.Errorf("no provider configured")
	}
	region := "us-east-1"
	if len(e.Regions) > 0 {
		region = e.Regions[0]
	}
	id, err := e.provider.GetAccountID(region)
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}
	e.accountID = id
	return nil
}

func (e *IAMEnumerator) getIAMClient() (*iam.Client, error) {
	region := "us-east-1"
	if len(e.Regions) > 0 {
		region = e.Regions[0]
	}
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	return iam.NewFromConfig(*cfg), nil
}

// listRoles fetches all IAM roles with pagination.
func (e *IAMEnumerator) listRoles(out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}
	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	var marker *string
	paginator := ratelimit.NewAWSPaginator()
	return paginator.Paginate(func() (bool, error) {
		input := &iam.ListRolesInput{}
		if marker != nil {
			input.Marker = marker
		}

		result, err := client.ListRoles(context.Background(), input)
		if err != nil {
			return false, fmt.Errorf("list IAM roles: %w", err)
		}

		for _, role := range result.Roles {
			name := aws.ToString(role.RoleName)
			roleARN := aws.ToString(role.Arn)
			if roleARN == "" {
				path := aws.ToString(role.Path)
				roleARN = fmt.Sprintf("arn:aws:iam::%s:role%s%s", e.accountID, path, name)
			}
			out.Send(output.AWSResource{
				ResourceType: "AWS::IAM::Role",
				ResourceID:   name,
				ARN:          roleARN,
				AccountRef:   e.accountID,
				Region:       "global",
			})
		}

		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})
}

// listPolicies fetches all customer-managed IAM policies with pagination.
func (e *IAMEnumerator) listPolicies(out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}
	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	var marker *string
	paginator := ratelimit.NewAWSPaginator()
	return paginator.Paginate(func() (bool, error) {
		input := &iam.ListPoliciesInput{
			Scope: types.PolicyScopeTypeLocal,
		}
		if marker != nil {
			input.Marker = marker
		}

		result, err := client.ListPolicies(context.Background(), input)
		if err != nil {
			return false, fmt.Errorf("list IAM policies: %w", err)
		}

		for _, policy := range result.Policies {
			name := aws.ToString(policy.PolicyName)
			policyARN := aws.ToString(policy.Arn)
			if policyARN == "" {
				path := aws.ToString(policy.Path)
				policyARN = fmt.Sprintf("arn:aws:iam::%s:policy%s%s", e.accountID, path, name)
			}
			out.Send(output.AWSResource{
				ResourceType: "AWS::IAM::Policy",
				ResourceID:   name,
				ARN:          policyARN,
				AccountRef:   e.accountID,
				Region:       "global",
			})
		}

		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})
}

// listUsers fetches all IAM users with pagination.
func (e *IAMEnumerator) listUsers(out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}
	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	var marker *string
	paginator := ratelimit.NewAWSPaginator()
	return paginator.Paginate(func() (bool, error) {
		input := &iam.ListUsersInput{}
		if marker != nil {
			input.Marker = marker
		}

		result, err := client.ListUsers(context.Background(), input)
		if err != nil {
			return false, fmt.Errorf("list IAM users: %w", err)
		}

		for _, user := range result.Users {
			name := aws.ToString(user.UserName)
			userARN := aws.ToString(user.Arn)
			if userARN == "" {
				path := aws.ToString(user.Path)
				userARN = fmt.Sprintf("arn:aws:iam::%s:user%s%s", e.accountID, path, name)
			}
			out.Send(output.AWSResource{
				ResourceType: "AWS::IAM::User",
				ResourceID:   name,
				ARN:          userARN,
				AccountRef:   e.accountID,
				Region:       "global",
			})

			fmt.Printf("sent user: %s\n", userARN)
		}

		if result.IsTruncated {
			marker = result.Marker
			return true, nil
		}
		return false, nil
	})
}

func (e *IAMEnumerator) getRoleByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}

	parts := strings.SplitN(arn, ":role", 2)
	if len(parts) != 2 {
		return errFallbackToCloudControl
	}
	segments := strings.Split(strings.TrimPrefix(parts[1], "/"), "/")
	roleName := segments[len(segments)-1]

	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	result, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return fmt.Errorf("get IAM role %s: %w", roleName, err)
	}

	out.Send(output.AWSResource{
		ResourceType: "AWS::IAM::Role",
		ResourceID:   aws.ToString(result.Role.RoleName),
		ARN:          aws.ToString(result.Role.Arn),
		AccountRef:   e.accountID,
		Region:       "global",
	})
	return nil
}

func (e *IAMEnumerator) getPolicyByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}

	if !strings.Contains(arn, ":policy") {
		return errFallbackToCloudControl
	}

	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	result, err := client.GetPolicy(context.Background(), &iam.GetPolicyInput{
		PolicyArn: &arn,
	})
	if err != nil {
		return fmt.Errorf("get IAM policy %s: %w", arn, err)
	}

	out.Send(output.AWSResource{
		ResourceType: "AWS::IAM::Policy",
		ResourceID:   aws.ToString(result.Policy.PolicyName),
		ARN:          aws.ToString(result.Policy.Arn),
		AccountRef:   e.accountID,
		Region:       "global",
	})
	return nil
}

func (e *IAMEnumerator) getUserByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	if err := e.resolveAccountID(); err != nil {
		return err
	}

	parts := strings.SplitN(arn, ":user", 2)
	if len(parts) != 2 {
		return errFallbackToCloudControl
	}
	segments := strings.Split(strings.TrimPrefix(parts[1], "/"), "/")
	userName := segments[len(segments)-1]

	client, err := e.getIAMClient()
	if err != nil {
		return err
	}

	result, err := client.GetUser(context.Background(), &iam.GetUserInput{
		UserName: &userName,
	})
	if err != nil {
		return fmt.Errorf("get IAM user %s: %w", userName, err)
	}

	out.Send(output.AWSResource{
		ResourceType: "AWS::IAM::User",
		ResourceID:   aws.ToString(result.User.UserName),
		ARN:          aws.ToString(result.User.Arn),
		AccountRef:   e.accountID,
		Region:       "global",
	})
	return nil
}
