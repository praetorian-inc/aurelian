package gaad

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AnalyzerState defines the interface for analyzer state access.
// Methods are used by the GaadAnalyzer's process methods (processUserPermissions,
// processRolePermissions, etc.) to look up cached data and evaluate permissions.
type AnalyzerState struct {
	Gaad        *types.AuthorizationAccountDetails
	OrgPolicies *orgpolicies.OrgPolicies
	Resources   store.Map[output.AWSResource]

	resourceStore  store.Map[*output.AWSResource]
	actionExpander *iam.ActionExpander
}

// AnalyzerMemoryState is a type alias for backward compatibility.
type AnalyzerMemoryState = AnalyzerState

// NewAnalyzerMemoryState is an alias for NewAnalyzerState for backward compatibility.
var NewAnalyzerMemoryState = NewAnalyzerState

func NewAnalyzerState(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources store.Map[output.AWSResource],
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
	s.initializeResourceCache()
}

func (s *AnalyzerState) initializeResourceCache() {
	s.resourceStore = store.NewMap[*output.AWSResource]()

	// Cloud resources from CloudControl
	s.Resources.Range(func(key string, r output.AWSResource) bool {
		s.resourceStore.Set(key, &r)
		return true
	})

	// IAM entities from GAAD (overwrite CloudControl versions; GAAD is authoritative for IAM)
	convertAndStore(s.Gaad.Roles, s.resourceStore, newAWSResourceFromRole)
	convertAndStore(s.Gaad.Policies, s.resourceStore, newAWSResourceFromPolicy)
	convertAndStore(s.Gaad.Users, s.resourceStore, newAWSResourceFromUser)
	convertAndStore(s.Gaad.Groups, s.resourceStore, newAWSResourceFromGroup)

	// Attacker resources used to identify cross-account access
	s.resourceStore.Set("attacker", &output.AWSResource{
		ResourceType: "AWS::API::Gateway",
		ResourceID:   "attacker",
		ARN:          "attacker",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	})
}

// convertAndStore iterates over a store.Map, converts each item to an
// *output.AWSResource, and stores it in dest keyed by the resource's ARN.
func convertAndStore[T any](src store.Map[T], dest store.Map[*output.AWSResource], convert func(T) *output.AWSResource) {
	src.Range(func(_ string, item T) bool {
		r := convert(item)
		dest.Set(r.ARN, r)
		return true
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
		s.resourceStore.Set(service, r)
		s.resourceStore.Set(serviceArn, r)
	}
}

// GetPolicyByArn retrieves a managed policy by its ARN.
func (s *AnalyzerState) GetPolicyByArn(policyArn string) *types.ManagedPolicyDetail {
	policy, ok := s.Gaad.Policies.Get(policyArn)
	if !ok {
		return nil
	}
	return &policy
}

func (s *AnalyzerState) getResources(pattern *regexp.Regexp) []*output.AWSResource {
	seen := make(map[string]bool)
	var resources []*output.AWSResource
	s.resourceStore.RangeWithKeyFilter(pattern.MatchString, func(key string, r *output.AWSResource) bool {
		id := r.ARN
		if !seen[id] {
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
	resource, ok := s.resourceStore.Get(resourceArn)
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
	v, ok := s.Gaad.Roles.Get(roleArn)
	if !ok {
		return nil
	}
	return &v
}

// GetResource returns a resource by ARN, or nil if not found.
func (s *AnalyzerState) GetResource(resourceArn string) *output.AWSResource {
	v, _ := s.resourceStore.Get(resourceArn)
	return v
}

// GetUser returns a user by ARN, or nil if not found.
func (s *AnalyzerState) GetUser(userArn string) *types.UserDetail {
	v, ok := s.Gaad.Users.Get(userArn)
	if !ok {
		return nil
	}
	return &v
}

// GetGroupByName returns a group by name, or nil if not found.
func (s *AnalyzerState) GetGroupByName(name string) *types.GroupDetail {
	var result *types.GroupDetail
	s.Gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		if g.GroupName == name {
			result = &g
			return false
		}
		return true
	})
	return result
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
