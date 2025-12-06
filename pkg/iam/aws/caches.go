package aws

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// Cache maps for faster lookups
var policyCache map[string]*types.PoliciesDL                    // ARN -> Policy
var roleCache map[string]*types.RoleDL                          // ARN -> Role
var userCache map[string]*types.UserDL                          // ARN -> User
var groupCache map[string]*types.GroupDL                        // ARN -> Group
var resourceCache map[string]*types.EnrichedResourceDescription // ARN -> Resource

func initializeCaches(pd *PolicyData) {
	var wg sync.WaitGroup

	// Add 5 tasks to the WaitGroup (one for each cache)
	wg.Add(5)

	// Launch each cache initialization in its own goroutine
	go initializePolicyCache(&wg, pd)
	go initializeRoleCache(&wg, pd)
	go initializeUserCache(&wg, pd)
	go initializeGroupCache(&wg, pd)
	go initializeResourceCache(&wg, pd)

	// Wait for all goroutines to complete
	wg.Wait()
}

func initializePolicyCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	policyCache = make(map[string]*types.PoliciesDL)
	for i := range pd.Gaad.Policies {
		policy := &pd.Gaad.Policies[i]
		policyCache[policy.Arn] = policy
	}
}

func initializeRoleCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	roleCache = make(map[string]*types.RoleDL)
	for i := range pd.Gaad.RoleDetailList {
		role := &pd.Gaad.RoleDetailList[i]
		roleCache[role.Arn] = role
	}
}

func initializeUserCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	userCache = make(map[string]*types.UserDL)
	for i := range pd.Gaad.UserDetailList {
		user := &pd.Gaad.UserDetailList[i]
		userCache[user.Arn] = user
	}
}

func initializeGroupCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	groupCache = make(map[string]*types.GroupDL)
	for i := range pd.Gaad.GroupDetailList {
		group := &pd.Gaad.GroupDetailList[i]
		groupCache[group.Arn] = group
	}
}

func initializeResourceCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	resourceCache = make(map[string]*types.EnrichedResourceDescription)
	if pd.Resources != nil {
		for i := range *pd.Resources {
			resource := &(*pd.Resources)[i]
			arn := resource.Arn.String()
			resourceCache[arn] = resource
		}
	}

	// Cloud Control doesn't return sufficient information to populate the resource cache
	// for IAM resources, so we need to do it manually
	for _, role := range pd.Gaad.RoleDetailList {
		resourceCache[role.Arn] = types.NewEnrichedResourceDescriptionFromRoleDL(role)
	}
	for _, policy := range pd.Gaad.Policies {
		resourceCache[policy.Arn] = types.NewEnrichedResourceDescriptionFromPolicyDL(policy)
	}
	for _, user := range pd.Gaad.UserDetailList {
		resourceCache[user.Arn] = types.NewEnrichedResourceDescriptionFromUserDL(user)
	}
	for _, group := range pd.Gaad.GroupDetailList {
		resourceCache[group.Arn] = types.NewEnrichedResourceDescriptionFromGroupDL(group)
	}

	// Create attacker resources used to identify cross-account access
	createAttackerResources(pd)
}

// addServicesToResourceCache adds common AWS services to the resource cache
func addServicesToResourceCache() {
	// List of common AWS services
	commonServices := []string{
		"s3.amazonaws.com",
		"lambda.amazonaws.com",
		"ec2.amazonaws.com",
		"iam.amazonaws.com",
		"dynamodb.amazonaws.com",
		"sns.amazonaws.com",
		"sqs.amazonaws.com",
		"cloudformation.amazonaws.com",
		"cloudtrail.amazonaws.com",
		"rds.amazonaws.com",
		"ssm.amazonaws.com",
		"kms.amazonaws.com",
		"secretsmanager.amazonaws.com",
		"codebuild.amazonaws.com",
		"codepipeline.amazonaws.com",
		"ecs.amazonaws.com",
		"eks.amazonaws.com",
		"glue.amazonaws.com",
		"sagemaker.amazonaws.com",
		"apigateway.amazonaws.com",
	}

	// Add services to the cache
	for _, service := range commonServices {

		// Create an EnrichedResourceDescription for the service
		resourceDescription := types.NewEnrichedResourceDescription(
			service,
			"AWS::Service",
			"*",
			"*",
			make(map[string]string),
		)

		// Add to resource cache
		resourceCache[service] = &resourceDescription
	}
}

// getPolicyByArn retrieves a policy using the cache
func getPolicyByArn(arn string) *types.PoliciesDL {
	if policy, ok := policyCache[arn]; ok {
		return policy
	}
	return nil
}

func getResources(pattern *regexp.Regexp) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	for arn := range resourceCache {
		if pattern.MatchString(arn) {
			resources = append(resources, resourceCache[arn])
		}
	}

	return resources
}

func getResourcesByAction(action Action) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	patterns := getResourcePatternsFromAction(action)

	for _, pattern := range patterns {
		resources = append(resources, getResources(pattern)...)
	}

	return resources
}

func getResourceDeets(resourceArn string) (string, map[string]string) {
	if strings.Contains(resourceArn, "amazonaws") {
		slog.Debug("Getting resource details for service", "service", resourceArn)
	}
	resource, ok := resourceCache[resourceArn]
	if !ok {
		slog.Debug("Resource not found for ARN", "arn", resourceArn)
		parsed, err := arn.Parse(resourceArn)
		if err != nil {
			slog.Error("Failed to parse ARN", "arn", resourceArn, "error", err)
			return "", nil
		}
		return parsed.AccountID, nil
	}
	return resource.AccountId, resource.Tags()
}

func getUserAttachedManagedPolicies(user types.UserDL) types.PolicyStatementList {
	identityStatements := types.PolicyStatementList{}
	for _, attachedPolicy := range user.AttachedManagedPolicies {
		if policy := getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
			for i := range policy.PolicyVersionList {
				if policy.PolicyVersionList[i].IsDefaultVersion {
					// Decorate with policy ARN
					for j := range *policy.PolicyVersionList[i].Document.Statement {
						(*policy.PolicyVersionList[i].Document.Statement)[j].OriginArn = attachedPolicy.PolicyArn
					}
					identityStatements = append(identityStatements, *policy.PolicyVersionList[i].Document.Statement...)
				}
			}
		}
	}
	return identityStatements
}

func getRoleAttachedManagedPolicies(role types.RoleDL) types.PolicyStatementList {
	identityStatements := types.PolicyStatementList{}
	// Iterate over the attached managed policies
	// and add their statements to the identityStatements list
	// Decorate with policy ARN
	for _, attachedPolicy := range role.AttachedManagedPolicies {
		if policy := getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
			if doc := policy.DefaultPolicyDocument(); doc != nil {
				// Decorate the policy with the role's ARN
				for stmt := range *doc.Statement {
					(*doc.Statement)[stmt].OriginArn = attachedPolicy.PolicyArn
				}
				identityStatements = append(identityStatements, *doc.Statement...)
			}
		}
	}
	return identityStatements
}

func createAttackerResources(pd *PolicyData) {
	for _, ar := range attackResources {
		resourceCache[ar.Arn.String()] = &ar
	}
}

var attackResources = []types.EnrichedResourceDescription{
	types.NewEnrichedResourceDescription("attacker", "AWS::API::Gateway", "us-east-1", "123456789012", make(map[string]string)),
}
