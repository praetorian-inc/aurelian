package gaad

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/cache"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AnalyzerState defines the interface for analyzer state access.
// Methods are used by the GaadAnalyzer's process methods (processUserPermissions,
// processRolePermissions, etc.) to look up cached data and evaluate permissions.
type AnalyzerState struct {
	Gaad        *types.AuthorizationAccountDetails
	OrgPolicies *orgpolicies.OrgPolicies
	Resources   []output.AWSResource

	policyCache    cache.Map[*types.ManagedPolicyDetail]
	roleCache      cache.Map[*types.RoleDetail]
	userCache      cache.Map[*types.UserDetail]
	groupCache     cache.Map[*types.GroupDetail]
	groupNameCache cache.Map[*types.GroupDetail] // keyed by GroupName
	resourceCache  cache.Map[*output.AWSResource]
	actionExpander *iam.ActionExpander
}

// AnalyzerMemoryState is a type alias for backward compatibility.
type AnalyzerMemoryState = AnalyzerState

// NewAnalyzerMemoryState is an alias for NewAnalyzerState for backward compatibility.
var NewAnalyzerMemoryState = NewAnalyzerState

func NewAnalyzerState(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources []output.AWSResource,
) *AnalyzerState {
	state := &AnalyzerState{
		Gaad:           gaad,
		OrgPolicies:    orgPolicies,
		Resources:      resources,
		actionExpander: &iam.ActionExpander{},
	}
	state.initializeCaches()
	state.addServicesToResourceCache()
	return state
}

func (s *AnalyzerState) initializeCaches() {
	var wg sync.WaitGroup
	wg.Add(5)
	go s.initializePolicyCache(&wg)
	go s.initializeRoleCache(&wg)
	go s.initializeUserCache(&wg)
	go s.initializeGroupCache(&wg)
	go s.initializeResourceCache(&wg)
	wg.Wait()
}

func (s *AnalyzerState) initializePolicyCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.policyCache = cache.NewMemoryMap[*types.ManagedPolicyDetail]()
	for i := range s.Gaad.Policies {
		policy := &s.Gaad.Policies[i]
		s.policyCache.Set(policy.Arn, policy)
	}
}

func (s *AnalyzerState) initializeRoleCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.roleCache = cache.NewMemoryMap[*types.RoleDetail]()
	for i := range s.Gaad.RoleDetailList {
		role := &s.Gaad.RoleDetailList[i]
		s.roleCache.Set(role.Arn, role)
	}
}

func (s *AnalyzerState) initializeUserCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.userCache = cache.NewMemoryMap[*types.UserDetail]()
	for i := range s.Gaad.UserDetailList {
		user := &s.Gaad.UserDetailList[i]
		s.userCache.Set(user.Arn, user)
	}
}

func (s *AnalyzerState) initializeGroupCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.groupCache = cache.NewMemoryMap[*types.GroupDetail]()
	s.groupNameCache = cache.NewMemoryMap[*types.GroupDetail]()
	for i := range s.Gaad.GroupDetailList {
		group := &s.Gaad.GroupDetailList[i]
		s.groupCache.Set(group.Arn, group)
		s.groupNameCache.Set(group.GroupName, group)
	}
}

func (s *AnalyzerState) initializeResourceCache(wg *sync.WaitGroup) {
	defer wg.Done()
	s.resourceCache = cache.NewMemoryMap[*output.AWSResource]()

	// Cloud resources from CloudControl
	for i := range s.Resources {
		r := &s.Resources[i]
		key := r.ARN
		if key == "" {
			key = r.ResourceID
		}
		s.resourceCache.Set(key, r)
	}

	// IAM entities from GAAD (overwrite CloudControl versions; GAAD is authoritative for IAM)
	for _, role := range s.Gaad.RoleDetailList {
		s.resourceCache.Set(role.Arn, newAWSResourceFromRole(role))
	}
	for _, policy := range s.Gaad.Policies {
		s.resourceCache.Set(policy.Arn, newAWSResourceFromPolicy(policy))
	}
	for _, user := range s.Gaad.UserDetailList {
		s.resourceCache.Set(user.Arn, newAWSResourceFromUser(user))
	}
	for _, group := range s.Gaad.GroupDetailList {
		s.resourceCache.Set(group.Arn, newAWSResourceFromGroup(group))
	}

	// Attacker resources used to identify cross-account access
	s.resourceCache.Set("attacker", &output.AWSResource{
		ResourceType: "AWS::API::Gateway",
		ResourceID:   "attacker",
		ARN:          "attacker",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	})
}

func (s *AnalyzerState) addServicesToResourceCache() {
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
			ResourceType: "AWS::Service",
			ResourceID:   service,
			ARN:          serviceArn,
			Region:       "*",
			AccountRef:   "*",
			DisplayName:  svc,
		}
		s.resourceCache.Set(service, r)
		s.resourceCache.Set(serviceArn, r)
	}
}

// GetPolicyByArn retrieves a managed policy by its ARN.
func (s *AnalyzerState) GetPolicyByArn(policyArn string) *types.ManagedPolicyDetail {
	policy, _ := s.policyCache.Get(policyArn)
	return policy
}

func (s *AnalyzerState) getResources(pattern *regexp.Regexp) []*output.AWSResource {
	seen := make(map[string]bool)
	var resources []*output.AWSResource
	s.resourceCache.Range(func(key string, r *output.AWSResource) bool {
		id := r.ARN
		if id == "" {
			id = r.ResourceID
		}
		if pattern.MatchString(key) && !seen[id] {
			seen[id] = true
			resources = append(resources, r)
		}
		return true
	})
	return resources
}

// GetResourcesByAction returns all cached resources whose ARN matches the action's resource patterns.
func (s *AnalyzerState) GetResourcesByAction(action iam.Action) []*output.AWSResource {
	var resources []*output.AWSResource
	patterns := iam.GetResourcePatternsFromAction(action)
	for _, pattern := range patterns {
		resources = append(resources, s.getResources(pattern)...)
	}
	return resources
}

// GetResourceDetails returns the account ID and tags for a resource ARN.
func (s *AnalyzerState) GetResourceDetails(resourceArn string) (string, map[string]string) {
	if strings.Contains(resourceArn, "amazonaws") {
		slog.Debug("Getting resource details for service", "service", resourceArn)
	}
	resource, ok := s.resourceCache.Get(resourceArn)
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
func (s *AnalyzerState) GetRole(roleArn string) *types.RoleDetail {
	v, _ := s.roleCache.Get(roleArn)
	return v
}

// GetResource returns a resource by ARN, or nil if not found.
func (s *AnalyzerState) GetResource(resourceArn string) *output.AWSResource {
	v, _ := s.resourceCache.Get(resourceArn)
	return v
}

// GetUser returns a user by ARN, or nil if not found.
func (s *AnalyzerState) GetUser(userArn string) *types.UserDetail {
	v, _ := s.userCache.Get(userArn)
	return v
}

// GetGroupByName returns a group by name, or nil if not found.
func (s *AnalyzerState) GetGroupByName(name string) *types.GroupDetail {
	v, _ := s.groupNameCache.Get(name)
	return v
}

// ExtractActions expands wildcard actions from policy statements using the ActionExpander.
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
