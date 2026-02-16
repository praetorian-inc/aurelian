package iam

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AnalyzerState holds all caches formerly stored as package-level globals.
type AnalyzerState struct {
	PolicyCache    map[string]*PoliciesDL
	RoleCache      map[string]*RoleDL
	UserCache      map[string]*UserDL
	GroupCache     map[string]*GroupDL
	ResourceCache  map[string]*types.EnrichedResourceDescription
	ActionExpander *ActionExpander
}

func NewAnalyzerState(pd *PolicyData) *AnalyzerState {
	state := &AnalyzerState{
		ActionExpander: &ActionExpander{},
	}
	state.initializeCaches(pd)
	state.addServicesToResourceCache()
	return state
}

func (s *AnalyzerState) initializeCaches(pd *PolicyData) {
	var wg sync.WaitGroup
	wg.Add(5)
	go s.initializePolicyCache(&wg, pd)
	go s.initializeRoleCache(&wg, pd)
	go s.initializeUserCache(&wg, pd)
	go s.initializeGroupCache(&wg, pd)
	go s.initializeResourceCache(&wg, pd)
	wg.Wait()
}

func (s *AnalyzerState) initializePolicyCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	s.PolicyCache = make(map[string]*PoliciesDL)
	for i := range pd.Gaad.Policies {
		policy := &pd.Gaad.Policies[i]
		s.PolicyCache[policy.Arn] = policy
	}
}

func (s *AnalyzerState) initializeRoleCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	s.RoleCache = make(map[string]*RoleDL)
	for i := range pd.Gaad.RoleDetailList {
		role := &pd.Gaad.RoleDetailList[i]
		s.RoleCache[role.Arn] = role
	}
}

func (s *AnalyzerState) initializeUserCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	s.UserCache = make(map[string]*UserDL)
	for i := range pd.Gaad.UserDetailList {
		user := &pd.Gaad.UserDetailList[i]
		s.UserCache[user.Arn] = user
	}
}

func (s *AnalyzerState) initializeGroupCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	s.GroupCache = make(map[string]*GroupDL)
	for i := range pd.Gaad.GroupDetailList {
		group := &pd.Gaad.GroupDetailList[i]
		s.GroupCache[group.Arn] = group
	}
}

func (s *AnalyzerState) initializeResourceCache(wg *sync.WaitGroup, pd *PolicyData) {
	defer wg.Done()
	s.ResourceCache = make(map[string]*types.EnrichedResourceDescription)
	if pd.Resources != nil {
		for i := range *pd.Resources {
			resource := &(*pd.Resources)[i]
			arn := resource.Arn.String()
			s.ResourceCache[arn] = resource
		}
	}

	// Cloud Control doesn't return sufficient information to populate the resource cache
	// for IAM resources, so we need to do it manually
	for _, role := range pd.Gaad.RoleDetailList {
		s.ResourceCache[role.Arn] = NewEnrichedResourceDescriptionFromRoleDL(role)
	}
	for _, policy := range pd.Gaad.Policies {
		s.ResourceCache[policy.Arn] = NewEnrichedResourceDescriptionFromPolicyDL(policy)
	}
	for _, user := range pd.Gaad.UserDetailList {
		s.ResourceCache[user.Arn] = NewEnrichedResourceDescriptionFromUserDL(user)
	}
	for _, group := range pd.Gaad.GroupDetailList {
		s.ResourceCache[group.Arn] = NewEnrichedResourceDescriptionFromGroupDL(group)
	}

	// Create attacker resources used to identify cross-account access
	s.createAttackerResources(pd)
}

// addServicesToResourceCache adds common AWS services to the resource cache
func (s *AnalyzerState) addServicesToResourceCache() {
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
		"autoscaling.amazonaws.com",
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
		s.ResourceCache[service] = &resourceDescription
	}
}

// getPolicyByArn retrieves a policy using the cache
func (s *AnalyzerState) getPolicyByArn(arn string) *PoliciesDL {
	if policy, ok := s.PolicyCache[arn]; ok {
		return policy
	}
	return nil
}

func (s *AnalyzerState) getResources(pattern *regexp.Regexp) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	for arn := range s.ResourceCache {
		if pattern.MatchString(arn) {
			resources = append(resources, s.ResourceCache[arn])
		}
	}
	return resources
}

func (s *AnalyzerState) getResourcesByAction(action Action) []*types.EnrichedResourceDescription {
	resources := make([]*types.EnrichedResourceDescription, 0)
	patterns := getResourcePatternsFromAction(action)

	for _, pattern := range patterns {
		resources = append(resources, s.getResources(pattern)...)
	}

	return resources
}

func (s *AnalyzerState) getResourceDeets(resourceArn string) (string, map[string]string) {
	if strings.Contains(resourceArn, "amazonaws") {
		slog.Debug("Getting resource details for service", "service", resourceArn)
	}
	resource, ok := s.ResourceCache[resourceArn]
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

func (s *AnalyzerState) getUserAttachedManagedPolicies(user UserDL) types.PolicyStatementList {
	identityStatements := types.PolicyStatementList{}
	for _, attachedPolicy := range user.AttachedManagedPolicies {
		if policy := s.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
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

func (s *AnalyzerState) getRoleAttachedManagedPolicies(role RoleDL) types.PolicyStatementList {
	identityStatements := types.PolicyStatementList{}
	// Iterate over the attached managed policies
	// and add their statements to the identityStatements list
	// Decorate with policy ARN
	for _, attachedPolicy := range role.AttachedManagedPolicies {
		if policy := s.getPolicyByArn(attachedPolicy.PolicyArn); policy != nil {
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

func (s *AnalyzerState) createAttackerResources(pd *PolicyData) {
	for _, ar := range attackResources {
		s.ResourceCache[ar.Arn.String()] = &ar
	}
}

// ExtractActions expands wildcard actions using the ActionExpander
func (s *AnalyzerState) ExtractActions(psl *types.PolicyStatementList) []string {
	actions := []string{}
	for _, statement := range *psl {
		if statement.Action != nil {
			expanded := s.expandActions(*statement.Action)
			actions = append(actions, expanded...)
		}
	}
	return actions
}

func (s *AnalyzerState) expandActions(actions types.DynaString) []string {
	expandedActions := make([]string, 0)
	for _, action := range actions {
		if strings.Contains(action, "*") {
			expanded, err := s.ActionExpander.Expand(action)
			if err != nil {
				slog.Error("Error expanding action", "action", action, "error", err)
				continue
			}
			expandedActions = append(expandedActions, expanded...)
		} else {
			expandedActions = append(expandedActions, action)
		}
	}
	return expandedActions
}

var attackResources = []types.EnrichedResourceDescription{
	types.NewEnrichedResourceDescription("attacker", "AWS::API::Gateway", "us-east-1", "123456789012", make(map[string]string)),
}
