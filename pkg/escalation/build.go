package escalation

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

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

	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		a, _ := arn.Parse(u.Arn)
		principals = append(principals, Principal{
			ARN:     u.Arn,
			Account: a.AccountID,
			Type:    PrincipalTypeUser,
			IsAdmin: isAdminUser(u, gaad),
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
func isAdminUser(user types.UserDetail, gaad *types.AuthorizationAccountDetails) bool {
	stmts := collectAllUserStatements(user, gaad)
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
	var stmts []types.PolicyStatement
	for _, p := range role.RolePolicyList {
		if p.PolicyDocument.Statement != nil {
			stmts = append(stmts, *p.PolicyDocument.Statement...)
		}
	}
	for _, mp := range role.AttachedManagedPolicies {
		policy, ok := gaad.Policies.Get(mp.PolicyArn)
		if !ok {
			continue
		}
		doc := policy.DefaultPolicyDocument()
		if doc != nil && doc.Statement != nil {
			stmts = append(stmts, *doc.Statement...)
		}
	}
	return stmts
}

// collectAllUserStatements gathers all identity policy statements for a user,
// including group policies.
func collectAllUserStatements(user types.UserDetail, gaad *types.AuthorizationAccountDetails) []types.PolicyStatement {
	var stmts []types.PolicyStatement
	for _, p := range user.UserPolicyList {
		if p.PolicyDocument.Statement != nil {
			stmts = append(stmts, *p.PolicyDocument.Statement...)
		}
	}
	for _, mp := range user.AttachedManagedPolicies {
		policy, ok := gaad.Policies.Get(mp.PolicyArn)
		if !ok {
			continue
		}
		doc := policy.DefaultPolicyDocument()
		if doc != nil && doc.Statement != nil {
			stmts = append(stmts, *doc.Statement...)
		}
	}
	// Include group policies
	for _, groupName := range user.GroupList {
		gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
			if g.GroupName != groupName {
				return true
			}
			for _, p := range g.GroupPolicyList {
				if p.PolicyDocument.Statement != nil {
					stmts = append(stmts, *p.PolicyDocument.Statement...)
				}
			}
			for _, mp := range g.AttachedManagedPolicies {
				policy, ok := gaad.Policies.Get(mp.PolicyArn)
				if !ok {
					return true
				}
				doc := policy.DefaultPolicyDocument()
				if doc != nil && doc.Statement != nil {
					stmts = append(stmts, *doc.Statement...)
				}
			}
			return false // found the group, stop
		})
	}
	return stmts
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

	// Group memberships: user → group
	gaad.Users.Range(func(_ string, u types.UserDetail) bool {
		for _, groupName := range u.GroupList {
			gaad.Groups.Range(func(_ string, g types.GroupDetail) bool {
				if g.GroupName == groupName {
					facts = append(facts, StructuralFact{
						Type:       FactGroupMembership,
						From:       u.Arn,
						To:         g.Arn,
						Confidence: 1.0,
					})
					return false
				}
				return true
			})
		}
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
		}
		return true
	})

	return facts
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

// CoverageTracker tracks which data sources were successfully collected.
type CoverageTracker struct {
	coverage CollectionCoverage
}

// NewCoverageTracker returns a new tracker with all flags set to false.
func NewCoverageTracker() *CoverageTracker {
	return &CoverageTracker{}
}

// MarkIAMGAAD marks IAM GAAD as collected.
func (ct *CoverageTracker) MarkIAMGAAD()                { ct.coverage.IAMGAAD = true }
func (ct *CoverageTracker) MarkEC2InstanceProfiles()     { ct.coverage.EC2InstanceProfiles = true }
func (ct *CoverageTracker) MarkLambdaExecutionRoles()    { ct.coverage.LambdaExecutionRoles = true }
func (ct *CoverageTracker) MarkECSTaskRoles()            { ct.coverage.ECSTaskRoles = true }
func (ct *CoverageTracker) MarkCodeBuildServiceRoles()   { ct.coverage.CodeBuildServiceRoles = true }
func (ct *CoverageTracker) MarkS3BucketPolicies()        { ct.coverage.S3BucketPolicies = true }
func (ct *CoverageTracker) MarkLambdaResourcePolicies()  { ct.coverage.LambdaResourcePolicies = true }
func (ct *CoverageTracker) MarkSQSQueuePolicies()        { ct.coverage.SQSQueuePolicies = true }
func (ct *CoverageTracker) MarkKMSKeyPolicies()          { ct.coverage.KMSKeyPolicies = true }
func (ct *CoverageTracker) MarkSNSTopicPolicies()        { ct.coverage.SNSTopicPolicies = true }

// Build returns the current coverage state.
func (ct *CoverageTracker) Build() *CollectionCoverage {
	return &ct.coverage
}

// MarkGAADCoverage is reserved for coverage flags derivable from GAAD alone.
// Note: ec2_instance_profiles is NOT set here — GAAD contains instance
// profile definitions but not EC2 instance associations. The flag is only
// set by MarkResourceTypes when EC2 instances are actually enumerated.
func (ct *CoverageTracker) MarkGAADCoverage(_ *types.AuthorizationAccountDetails) {
	// Currently a no-op. Future: could mark coverage for data only derivable
	// from GAAD (e.g., permission boundaries).
}

// MarkResourceTypes marks coverage for resource types found in the collected resources.
func (ct *CoverageTracker) MarkResourceTypes(resources store.Map[output.AWSResource]) {
	resources.Range(func(_ string, r output.AWSResource) bool {
		switch r.ResourceType {
		case "AWS::Lambda::Function":
			ct.coverage.LambdaExecutionRoles = true
			if r.ResourcePolicy != nil {
				ct.coverage.LambdaResourcePolicies = true
			}
		case "AWS::EC2::Instance":
			ct.coverage.EC2InstanceProfiles = true
		case "AWS::CodeBuild::Project":
			ct.coverage.CodeBuildServiceRoles = true
		case "AWS::S3::Bucket":
			if r.ResourcePolicy != nil {
				ct.coverage.S3BucketPolicies = true
			}
		case "AWS::SQS::Queue":
			if r.ResourcePolicy != nil {
				ct.coverage.SQSQueuePolicies = true
			}
		case "AWS::SNS::Topic":
			if r.ResourcePolicy != nil {
				ct.coverage.SNSTopicPolicies = true
			}
		case "AWS::KMS::Key":
			if r.ResourcePolicy != nil {
				ct.coverage.KMSKeyPolicies = true
			}
		case "AWS::ECS::TaskDefinition":
			ct.coverage.ECSTaskRoles = true
		}
		return true
	})
}
