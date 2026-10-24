package escalation

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// BuildGroupsByName creates an index of GAAD groups keyed by GroupName for O(1)
// lookup. The GAAD Groups store.Map is keyed by ARN, so looking up by name
// requires a linear scan; callers that resolve user.GroupList entries should
// build this index once and reuse it.
func BuildGroupsByName(gaad *types.AuthorizationAccountDetails) map[string]types.GroupDetail {
	groups := make(map[string]types.GroupDetail)
	gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		groups[g.GroupName] = g
		return true
	})
	return groups
}

// awsResourceTypeToSolver maps Aurelian CloudControl resource types to the
// solver's resource type enum.
var awsResourceTypeToSolver = map[string]ResourceType{
	"AWS::Lambda::Function":    ResourceTypeLambdaFunction,
	"AWS::EC2::Instance":       ResourceTypeEC2Instance,
	"AWS::S3::Bucket":          ResourceTypeS3Bucket,
	"AWS::CodeBuild::Project":  ResourceTypeCodeBuildProject,
	"AWS::ECS::TaskDefinition": ResourceTypeECSTask,
	"AWS::SQS::Queue":          ResourceTypeSQSQueue,
	"AWS::SNS::Topic":          ResourceTypeSNSTopic,
	"AWS::KMS::Key":            ResourceTypeKMSKey,
}

// ---------------------------------------------------------------------------
// Principals (A.2)
// ---------------------------------------------------------------------------

// CollectPrincipals transforms GAAD principals into model-v1 Principal structs.
func CollectPrincipals(gaad *types.AuthorizationAccountDetails) []Principal {
	var principals []Principal
	groupsByName := BuildGroupsByName(gaad)

	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		a, _ := arn.Parse(u.Arn)
		principals = append(principals, Principal{
			ARN:     u.Arn,
			Account: a.AccountID,
			Type:    PrincipalTypeUser,
			IsAdmin: isAdminUser(u, gaad, groupsByName),
		})
		return true
	})

	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		a, _ := arn.Parse(r.Arn)
		principals = append(principals, Principal{
			ARN:     r.Arn,
			Account: a.AccountID,
			Type:    PrincipalTypeRole,
			IsAdmin: isAdminRole(r, gaad),
		})
		return true
	})

	gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		a, _ := arn.Parse(g.Arn)
		principals = append(principals, Principal{
			ARN:     g.Arn,
			Account: a.AccountID,
			Type:    PrincipalTypeGroup,
			IsAdmin: isAdminGroup(g, gaad),
		})
		return true
	})

	return principals
}

// isAdminRole returns true if the role has admin-level access.
// Conservative: false negatives are acceptable.
func isAdminRole(role types.RoleDetail, gaad *types.AuthorizationAccountDetails) bool {
	stmts := collectAllRoleStatements(role, gaad)
	return isAdmin(stmts)
}

// isAdminUser returns true if the user (including group policies) has
// admin-level access.
func isAdminUser(user types.UserDetail, gaad *types.AuthorizationAccountDetails, groupsByName map[string]types.GroupDetail) bool {
	stmts := collectAllUserStatements(user, gaad, groupsByName)
	return isAdmin(stmts)
}

// isAdminGroup returns true if the group's own policies grant admin-level access.
func isAdminGroup(group types.GroupDetail, gaad *types.AuthorizationAccountDetails) bool {
	stmts := collectAllGroupStatements(group, gaad)
	return isAdmin(stmts)
}

// isAdmin checks two heuristics from the spec (section 3.3):
//  1. Allow *:* on * without a restricting deny, OR
//  2. iam:* on * plus sts:AssumeRole on * (without a restricting deny)
func isAdmin(stmts []types.PolicyStatement) bool {
	hasStarAllow := false
	hasStarDeny := false
	hasIAMStar := false
	hasAssumeRoleStar := false

	for _, s := range stmts {
		starAction := actionMatchesStar(s.Action)
		starResource := resourceMatchesStar(s.Resource)

		if strings.EqualFold(s.Effect, "Allow") && s.Condition == nil && starResource {
			if starAction {
				hasStarAllow = true
			}
			if actionMatchesPattern(s.Action, "iam:*") {
				hasIAMStar = true
			}
			if actionMatchesPattern(s.Action, "sts:AssumeRole") {
				hasAssumeRoleStar = true
			}
		}
		if strings.EqualFold(s.Effect, "Deny") && starAction && starResource {
			hasStarDeny = true
		}
	}

	if hasStarDeny {
		return false
	}
	return hasStarAllow || (hasIAMStar && hasAssumeRoleStar)
}

func actionMatchesStar(action *types.DynaString) bool {
	if action == nil {
		return false
	}
	for _, a := range *action {
		if a == "*" {
			return true
		}
	}
	return false
}

// actionMatchesPattern returns true if any action in the list matches the
// pattern (case-insensitive). The pattern may be a literal like "sts:AssumeRole"
// or a wildcard like "iam:*". The action list may contain wildcards too (e.g.
// "*" matches everything, "iam:*" matches "iam:*").
func actionMatchesPattern(action *types.DynaString, pattern string) bool {
	if action == nil {
		return false
	}
	pattern = strings.ToLower(pattern)
	for _, a := range *action {
		lower := strings.ToLower(a)
		// "*" covers everything
		if lower == "*" {
			return true
		}
		// "iam:*" covers "iam:*", "iam:CreateUser", etc.
		if strings.HasSuffix(lower, ":*") && strings.HasPrefix(pattern, strings.TrimSuffix(lower, "*")) {
			return true
		}
		// Direct match
		if lower == pattern {
			return true
		}
	}
	return false
}

func resourceMatchesStar(resource *types.DynaString) bool {
	if resource == nil {
		return false
	}
	for _, r := range *resource {
		if r == "*" {
			return true
		}
	}
	return false
}

// collectAllRoleStatements gathers all identity policy statements for a role.
func collectAllRoleStatements(role types.RoleDetail, gaad *types.AuthorizationAccountDetails) []types.PolicyStatement {
	return CollectRawRoleStatements(&role, GAADPolicyResolver(gaad))
}

// collectAllGroupStatements gathers all identity policy statements for a group
// (inline + attached-managed).
func collectAllGroupStatements(group types.GroupDetail, gaad *types.AuthorizationAccountDetails) []types.PolicyStatement {
	return CollectRawGroupStatements(&group, GAADPolicyResolver(gaad))
}

// collectAllUserStatements gathers all identity policy statements for a user,
// including group policies.
func collectAllUserStatements(user types.UserDetail, gaad *types.AuthorizationAccountDetails, groupsByName map[string]types.GroupDetail) []types.PolicyStatement {
	return CollectRawUserStatements(&user, groupsByName, GAADPolicyResolver(gaad))
}

// ---------------------------------------------------------------------------
// Resources (A.3)
// ---------------------------------------------------------------------------

// CollectResources transforms Aurelian AWSResource objects into model-v1
// Resource structs. Only resources with a known solver type mapping are included.
func CollectResources(resources store.Map[output.AWSResource]) []Resource {
	var result []Resource
	resources.Range(func(_ string, r output.AWSResource) bool {
		solverType, ok := awsResourceTypeToSolver[r.ResourceType]
		if !ok {
			return true // skip unknown types
		}
		result = append(result, Resource{
			ARN:     r.ARN,
			Type:    solverType,
			Account: r.AccountRef,
		})
		return true
	})
	return result
}

// ---------------------------------------------------------------------------
// Structural Facts (A.4)
// ---------------------------------------------------------------------------

// CollectStructuralFacts extracts non-permission relationships from GAAD data
// and resources.
func CollectStructuralFacts(gaad *types.AuthorizationAccountDetails, resources store.Map[output.AWSResource]) []StructuralFact {
	var facts []StructuralFact
	groupsByName := BuildGroupsByName(gaad)

	// Group memberships: user → group
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		for _, groupName := range u.GroupList {
			if g, ok := groupsByName[groupName]; ok {
				facts = append(facts, StructuralFact{
					Type:       FactGroupMembership,
					From:       u.Arn,
					To:         g.Arn,
					Confidence: 1.0,
				})
			}
		}
		return true
	})

	// Policy attachments: customer-managed policy ARN → principal ARN.
	// AWS-managed policies cannot be rewritten via CreatePolicyVersion.
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		facts = appendPolicyAttachmentFacts(facts, u.Arn, u.AttachedManagedPolicies)
		return true
	})
	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		facts = appendPolicyAttachmentFacts(facts, r.Arn, r.AttachedManagedPolicies)
		return true
	})
	gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
		facts = appendPolicyAttachmentFacts(facts, g.Arn, g.AttachedManagedPolicies)
		return true
	})

	// Trust relationships: from role being assumed → to principal trusted to assume it
	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		if r.AssumeRolePolicyDocument.Statement == nil {
			return true
		}
		for _, stmt := range *r.AssumeRolePolicyDocument.Statement {
			if !strings.EqualFold(stmt.Effect, "Allow") {
				continue
			}
			for _, p := range stmt.ExtractPrincipals() {
				if p == "" || !arn.IsARN(p) {
					continue
				}
				facts = append(facts, StructuralFact{
					Type:       FactTrustRelationship,
					From:       r.Arn,
					To:         p,
					Confidence: 1.0,
				})
			}
		}
		return true
	})

	// Instance profiles: build IP ARN → role ARN(s) index from GAAD, then
	// resolve EC2 instances through to their roles. Per spec section 3.5,
	// from = EC2 instance ARN, to = IAM role ARN.
	ipToRoles := make(map[string][]string)
	gaad.Roles.Range(func(_ string, r types.RoleDetail) bool {
		for _, ip := range r.InstanceProfileList {
			for _, ipr := range ip.Roles {
				ipToRoles[ip.Arn] = append(ipToRoles[ip.Arn], ipr.Arn)
			}
			// Also index by instance profile name for CloudControl lookups
			// where the property may be a name or ID rather than a full ARN.
			ipToRoles[ip.InstanceProfileName] = ipToRoles[ip.Arn]
		}
		return true
	})

	// Lambda execution roles, CodeBuild service roles, EC2 instance profiles,
	// ECS task roles: from resource properties.
	resources.Range(func(_ string, r output.AWSResource) bool {
		switch r.ResourceType {
		case "AWS::Lambda::Function":
			if roleARN, ok := extractProperty(r, "Role"); ok {
				facts = append(facts, StructuralFact{
					Type:       FactLambdaExecutionRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::CodeBuild::Project":
			if roleARN, ok := extractProperty(r, "ServiceRole"); ok {
				facts = append(facts, StructuralFact{
					Type:       FactCodeBuildServiceRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::EC2::Instance":
			if profileRef, ok := extractProperty(r, "IamInstanceProfile"); ok {
				// Resolve instance profile → role(s) via the GAAD index.
				if roles, found := ipToRoles[profileRef]; found {
					for _, roleARN := range roles {
						facts = append(facts, StructuralFact{
							Type:       FactInstanceProfile,
							From:       r.ARN,
							To:         roleARN,
							Confidence: 1.0,
						})
					}
				}
			}
		case "AWS::ECS::TaskDefinition":
			if roleARN, ok := extractProperty(r, "TaskRoleArn"); ok {
				facts = append(facts, StructuralFact{
					Type:       FactECSTaskRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::Athena::WorkGroup":
			if roleARN, ok := extractProperty(r, "ExecutionRole"); ok && roleARN != "" {
				facts = append(facts, StructuralFact{
					Type:       FactAthenaWorkgroupRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::SageMaker::Space":
			roleARN, ok := extractProperty(r, "ExecutionRole")
			if roleARN == "" {
				roleARN, ok = extractProperty(r, "ExecutionRoleArn")
			}
			if ok && roleARN != "" {
				facts = append(facts, StructuralFact{
					Type:       FactSageMakerSpaceRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::Glue::DevEndpoint":
			if roleARN, ok := extractProperty(r, "RoleArn"); ok && roleARN != "" {
				facts = append(facts, StructuralFact{
					Type:       FactGlueEndpointRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::SageMaker::NotebookInstance":
			if roleARN, ok := extractProperty(r, "RoleArn"); ok && roleARN != "" {
				facts = append(facts, StructuralFact{
					Type:       FactSageMakerNotebookRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		case "AWS::BedrockAgentCore::CodeInterpreter":
			if roleARN, ok := extractProperty(r, "ExecutionRoleArn"); ok && roleARN != "" {
				facts = append(facts, StructuralFact{
					Type:       FactBedrockInterpreterRole,
					From:       r.ARN,
					To:         roleARN,
					Confidence: 1.0,
				})
			}
		}
		return true
	})

	return facts
}

// appendPolicyAttachmentFacts emits policy_attachment facts for customer-managed
// IAM policies attached to a principal. from = policy ARN, to = principal ARN.
func appendPolicyAttachmentFacts(facts []StructuralFact, principalARN string, attached []types.ManagedPolicy) []StructuralFact {
	for _, mp := range attached {
		if !isCustomerManagedPolicyARN(mp.PolicyArn) {
			continue
		}
		facts = append(facts, StructuralFact{
			Type:       FactPolicyAttachment,
			From:       mp.PolicyArn,
			To:         principalARN,
			Confidence: 1.0,
		})
	}
	return facts
}

// isCustomerManagedPolicyARN reports whether policyARN is a rewriteable IAM
// managed policy. Empty ARNs, non-IAM/non-policy ARNs, and AWS-managed
// policies (account "aws") are rejected. Uses proper ARN parsing to avoid
// false positives from substring matching.
func isCustomerManagedPolicyARN(policyARN string) bool {
	parsed, err := arn.Parse(policyARN)
	if err != nil {
		return false
	}
	if parsed.Service != "iam" {
		return false
	}
	if parsed.AccountID == "aws" {
		return false
	}
	return strings.HasPrefix(parsed.Resource, "policy/")
}

// extractProperty returns a string property from an AWSResource's Properties map.
func extractProperty(r output.AWSResource, key string) (string, bool) {
	if r.Properties == nil {
		return "", false
	}
	v, ok := r.Properties[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// ---------------------------------------------------------------------------
// Resource Policies (pass-through)
// ---------------------------------------------------------------------------

// CollectResourcePolicies extracts resource-based policies from collected
// resources that have them.
func CollectResourcePolicies(resources store.Map[output.AWSResource]) []ResourcePolicy {
	var policies []ResourcePolicy
	resources.Range(func(_ string, r output.AWSResource) bool {
		if r.ResourcePolicy != nil && r.ARN != "" {
			policies = append(policies, ResourcePolicy{
				Resource: r.ARN,
				Policy:   r.ResourcePolicy,
			})
		}
		return true
	})
	return policies
}

// ---------------------------------------------------------------------------
// Collection Coverage (A.6)
// ---------------------------------------------------------------------------

// CoverageTracker tracks which data sources were attempted and any errors.
// Coverage semantics: true = attempted (even if zero results), false/absent =
// not attempted. Errors record partial failures.
type CoverageTracker struct {
	coverage CollectionCoverage
	errors   []CollectionError
}

// NewCoverageTracker returns a new tracker with all flags set to false.
func NewCoverageTracker() *CoverageTracker {
	return &CoverageTracker{}
}

// MarkIAMGAAD marks IAM GAAD as attempted.
func (ct *CoverageTracker) MarkIAMGAAD() { ct.coverage.IAMGAAD = true }

// MarkAttempted marks a resource type as attempted. Call this for every type
// the enumerator tried, regardless of whether it found results.
func (ct *CoverageTracker) MarkAttempted(resourceType string) {
	switch resourceType {
	case "AWS::Lambda::Function":
		ct.coverage.LambdaExecutionRoles = true
		ct.coverage.LambdaResourcePolicies = true
	case "AWS::EC2::Instance":
		ct.coverage.EC2InstanceProfiles = true
	case "AWS::CodeBuild::Project":
		ct.coverage.CodeBuildServiceRoles = true
	case "AWS::ECS::TaskDefinition":
		ct.coverage.ECSTaskRoles = true
	case "AWS::S3::Bucket":
		ct.coverage.S3BucketPolicies = true
	case "AWS::SQS::Queue":
		ct.coverage.SQSQueuePolicies = true
	case "AWS::SNS::Topic":
		ct.coverage.SNSTopicPolicies = true
	case "AWS::KMS::Key":
		ct.coverage.KMSKeyPolicies = true
	}
}

// RecordError records a collection failure for a data source.
func (ct *CoverageTracker) RecordError(source, errMsg string, regions ...string) {
	ct.errors = append(ct.errors, CollectionError{
		Source:  source,
		Error:   errMsg,
		Regions: regions,
	})
}

// Build returns the current coverage state.
func (ct *CoverageTracker) Build() *CollectionCoverage {
	return &ct.coverage
}

// Errors returns any collection errors recorded.
func (ct *CoverageTracker) Errors() []CollectionError {
	return ct.errors
}
