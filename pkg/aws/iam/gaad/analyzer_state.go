package gaad

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AnalyzerState defines the interface for analyzer state access.
// Methods are used by the GaadAnalyzer's process methods (processUserPermissions,
// processRolePermissions, etc.) to look up cached data and evaluate permissions.
type AnalyzerState interface {
	GetPolicyByArn(policyArn string) *types.ManagedPolicyDetail
	ExtractActions(psl *types.PolicyStatementList) []string
	GetResourcesByAction(action iam.Action) []*output.AWSResource
	GetResourceDetails(resourceArn string) (string, map[string]string)
	GetRole(arn string) *types.RoleDetail
	GetResource(arn string) *output.AWSResource
	GetGroupByName(name string) *types.GroupDetail
	GetUser(arn string) *types.UserDetail
}

// AnalyzerMemoryState is the in-memory implementation of AnalyzerState.
type AnalyzerMemoryState struct {
	Gaad        *types.AuthorizationAccountDetails
	OrgPolicies *orgpolicies.OrgPolicies
	Resources   []output.AWSResource

	policyCache    map[string]*types.ManagedPolicyDetail
	roleCache      map[string]*types.RoleDetail
	userCache      map[string]*types.UserDetail
	groupCache     map[string]*types.GroupDetail
	groupNameCache map[string]*types.GroupDetail // keyed by GroupName
	resourceCache  map[string]*output.AWSResource
	actionExpander *iam.ActionExpander
}

func NewAnalyzerMemoryState(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources []output.AWSResource,
) *AnalyzerMemoryState {
	state := &AnalyzerMemoryState{
		Gaad:           gaad,
		OrgPolicies:    orgPolicies,
		Resources:      resources,
		actionExpander: &iam.ActionExpander{},
	}
	state.initializeCaches()
	state.addServicesToResourceCache()
	return state
}

func (s *AnalyzerMemoryState) initializeCaches() {
	var wg sync.WaitGroup
	wg.Add(5)
	go s.initializePolicyCache(&wg)
	go s.initializeRoleCache(&wg)
	go s.initializeUserCache(&wg)
	go s.initializeGroupCache(&wg)
	go s.initializeResourceCache(&wg)
	wg.Wait()
}

func (s *AnalyzerMemoryState) initializePolicyCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.policyCache = make(map[string]*types.ManagedPolicyDetail)
	for i := range s.Gaad.Policies {
		policy := &s.Gaad.Policies[i]
		s.policyCache[policy.Arn] = policy
	}
}

func (s *AnalyzerMemoryState) initializeRoleCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.roleCache = make(map[string]*types.RoleDetail)
	for i := range s.Gaad.RoleDetailList {
		role := &s.Gaad.RoleDetailList[i]
		s.roleCache[role.Arn] = role
	}
}

func (s *AnalyzerMemoryState) initializeUserCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.userCache = make(map[string]*types.UserDetail)
	for i := range s.Gaad.UserDetailList {
		user := &s.Gaad.UserDetailList[i]
		s.userCache[user.Arn] = user
	}
}

func (s *AnalyzerMemoryState) initializeGroupCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.groupCache = make(map[string]*types.GroupDetail)
	s.groupNameCache = make(map[string]*types.GroupDetail)
	for i := range s.Gaad.GroupDetailList {
		group := &s.Gaad.GroupDetailList[i]
		s.groupCache[group.Arn] = group
		s.groupNameCache[group.GroupName] = group
	}
}

func (s *AnalyzerMemoryState) initializeResourceCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.resourceCache = make(map[string]*output.AWSResource)

	// Cloud resources from CloudControl
	for i := range s.Resources {
		r := &s.Resources[i]
		key := r.ARN
		if key == "" {
			key = r.ResourceID
		}
		s.resourceCache[key] = r
	}

	// IAM entities from GAAD (overwrite CloudControl versions; GAAD is authoritative for IAM)
	for _, role := range s.Gaad.RoleDetailList {
		s.resourceCache[role.Arn] = newAWSResourceFromRole(role)
	}
	for _, policy := range s.Gaad.Policies {
		s.resourceCache[policy.Arn] = newAWSResourceFromPolicy(policy)
	}
	for _, user := range s.Gaad.UserDetailList {
		s.resourceCache[user.Arn] = newAWSResourceFromUser(user)
	}
	for _, group := range s.Gaad.GroupDetailList {
		s.resourceCache[group.Arn] = newAWSResourceFromGroup(group)
	}

	// Attacker resources used to identify cross-account access
	s.resourceCache["attacker"] = &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::API::Gateway",
		ResourceID:   "attacker",
		ARN:          "attacker",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	}
}

func (s *AnalyzerMemoryState) addServicesToResourceCache() {
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

	for _, service := range commonServices {
		svc := strings.Split(service, ".")[0]
		serviceArn := types.BuildResourceARN(service, "AWS::Service", "*", "*").String()
		r := &output.AWSResource{
			Platform:     "aws",
			ResourceType: "AWS::Service",
			ResourceID:   service,
			ARN:          serviceArn,
			Region:       "*",
			AccountRef:   "*",
			DisplayName:  svc,
		}
		s.resourceCache[service] = r
		s.resourceCache[serviceArn] = r
	}
}

// GetPolicyByArn retrieves a managed policy by its ARN.
func (s *AnalyzerMemoryState) GetPolicyByArn(policyArn string) *types.ManagedPolicyDetail {
	if policy, ok := s.policyCache[policyArn]; ok {
		return policy
	}
	return nil
}

func (s *AnalyzerMemoryState) getResources(pattern *regexp.Regexp) []*output.AWSResource {
	seen := make(map[*output.AWSResource]bool)
	var resources []*output.AWSResource
	for key, r := range s.resourceCache {
		if pattern.MatchString(key) && !seen[r] {
			seen[r] = true
			resources = append(resources, r)
		}
	}
	return resources
}

// GetResourcesByAction returns all cached resources whose ARN matches the action's resource patterns.
func (s *AnalyzerMemoryState) GetResourcesByAction(action iam.Action) []*output.AWSResource {
	var resources []*output.AWSResource
	patterns := iam.GetResourcePatternsFromAction(action)
	for _, pattern := range patterns {
		resources = append(resources, s.getResources(pattern)...)
	}
	return resources
}

// GetResourceDetails returns the account ID and tags for a resource ARN.
func (s *AnalyzerMemoryState) GetResourceDetails(resourceArn string) (string, map[string]string) {
	if strings.Contains(resourceArn, "amazonaws") {
		slog.Debug("Getting resource details for service", "service", resourceArn)
	}
	resource, ok := s.resourceCache[resourceArn]
	if !ok {
		slog.Debug("Resource not found for ARN", "arn", resourceArn)
		parsed, err := arn.Parse(resourceArn)
		if err != nil {
			slog.Error("Failed to parse ARN", "arn", resourceArn, "error", err)
			return "", nil
		}
		return parsed.AccountID, nil
	}
	return resource.AccountRef, extractResourceTags(resource)
}

// GetRole returns a role by ARN, or nil if not found.
func (s *AnalyzerMemoryState) GetRole(roleArn string) *types.RoleDetail {
	return s.roleCache[roleArn]
}

// GetResource returns a resource by ARN, or nil if not found.
func (s *AnalyzerMemoryState) GetResource(resourceArn string) *output.AWSResource {
	return s.resourceCache[resourceArn]
}

// GetUser returns a user by ARN, or nil if not found.
func (s *AnalyzerMemoryState) GetUser(userArn string) *types.UserDetail {
	return s.userCache[userArn]
}

// GetGroupByName returns a group by name, or nil if not found.
func (s *AnalyzerMemoryState) GetGroupByName(name string) *types.GroupDetail {
	return s.groupNameCache[name]
}

// ExtractActions expands wildcard actions from policy statements using the ActionExpander.
func (s *AnalyzerMemoryState) ExtractActions(psl *types.PolicyStatementList) []string {
	actions := []string{}
	for _, statement := range *psl {
		if statement.Action != nil {
			expanded := s.expandActions(*statement.Action)
			actions = append(actions, expanded...)
		}
	}
	return actions
}

func (s *AnalyzerMemoryState) expandActions(actions types.DynaString) []string {
	expandedActions := make([]string, 0)
	for _, action := range actions {
		if strings.Contains(action, "*") {
			expanded, err := s.actionExpander.Expand(action)
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
