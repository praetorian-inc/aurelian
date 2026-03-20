package iamadmin

import (
	"context"
	"fmt"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// Evaluator checks whether IAM principals have administrator access.
type Evaluator struct {
	cfg          plugin.AWSCommonRecon
	iam          *iam.Client
	initMu       sync.Mutex
	emittedUsers map[string]bool
}

func New(cfg plugin.AWSCommonRecon) *Evaluator {
	return &Evaluator{
		cfg:          cfg,
		emittedUsers: map[string]bool{},
	}
}

func (e *Evaluator) EvaluatePrincipal(principal output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	if err := e.initialize(); err != nil {
		return err
	}

	switch principal.ResourceType {
	case "AWS::IAM::User":
		return e.emitAdminUser(principal, out)
	case "AWS::IAM::Role":
		return e.emitAdminRole(principal, out)
	case "AWS::IAM::Group":
		return e.emitAdminGroup(principal, out)
	default:
		return fmt.Errorf("resource type %s is not a principal", principal.ResourceType)
	}
}

func (e *Evaluator) initialize() error {
	e.initMu.Lock()
	defer e.initMu.Unlock()

	if e.iam != nil {
		return nil
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    e.cfg.Profile,
		ProfileDir: e.cfg.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	e.iam = iam.NewFromConfig(awsCfg)

	return nil
}

func (e *Evaluator) IsUserAdmin(ctx context.Context, userName string) (bool, error) {
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

func (e *Evaluator) IsRoleAdmin(ctx context.Context, roleName string) (bool, error) {
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

func (e *Evaluator) IsGroupAdmin(ctx context.Context, groupName string) (bool, error) {
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

func (e *Evaluator) GroupMembers(ctx context.Context, groupName string) ([]string, error) {
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

func (e *Evaluator) emitAdminUser(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.IsUserAdmin(context.Background(), resource.ResourceID)
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

func (e *Evaluator) emitAdminRole(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.IsRoleAdmin(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate role %s: %w", resource.ResourceID, err)
	}
	if !isAdmin {
		return nil
	}

	resource.IsAdmin = true
	out.Send(resource)
	return nil
}

func (e *Evaluator) emitAdminGroup(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	isAdmin, err := e.IsGroupAdmin(context.Background(), resource.ResourceID)
	if err != nil {
		return fmt.Errorf("evaluate group %s: %w", resource.ResourceID, err)
	}
	if !isAdmin {
		return nil
	}

	resource.IsAdmin = true
	out.Send(resource)

	members, err := e.GroupMembers(context.Background(), resource.ResourceID)
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
