//go:build integration

package analyze

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/integration/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Register graph module
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/analyze"
)

// TestGraphValidation_PrivescDetection runs the full graph pipeline against
// Terraform-provisioned IAM infrastructure and validates that privilege
// escalation paths are correctly detected in the Neo4j graph.
//
// Flow: TerraformFixture → graph module → GraphFormatter → Neo4j → Cypher validation
//
// Requires:
//   - AWS credentials (via AWS_PROFILE or environment)
//   - terraform in PATH
//   - ~15-30 min timeout (IAM provisioning + GAAD collection + resource enumeration)
func TestGraphValidation_PrivescDetection(t *testing.T) {
	ctx := context.Background()

	// Step 1: Provision IAM infrastructure via Terraform
	fixture := testutil.NewFixture(t, "aws/graph")
	fixture.Setup()

	suffix := fixture.Output("random_suffix")
	region := fixture.Output("region")
	t.Logf("Terraform infrastructure deployed (suffix=%s, region=%s)", suffix, region)

	// Step 2: Use shared Neo4j container
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	boltURL := sharedNeo4jBoltURL
	t.Logf("Using shared Neo4j container at %s", boltURL)

	// Step 3: Run graph module against the AWS account
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryAnalyze, "graph")
	if !ok {
		t.Fatal("graph module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{region},
		},
		Context: ctx,
	})
	require.NoError(t, err)
	require.NotEmpty(t, results, "graph module should return results")
	t.Logf("Graph module returned %d result sets", len(results))

	// Step 4: Populate Neo4j via GraphFormatter
	formatter, err := plugin.NewGraphFormatter(boltURL, "", "")
	require.NoError(t, err)
	defer formatter.Close()

	err = formatter.Format(results)
	require.NoError(t, err)
	t.Log("Graph populated in Neo4j")

	// Step 5: Create adapter for validation queries
	cfg := graph.NewConfig(boltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	defer adapter.Close()

	// Step 6: Run privilege escalation validation queries
	//
	// Each test validates that a specific privilege escalation path was detected
	// in the graph. Relationship types are normalized: iam:Action → IAM_ACTION.
	// Property names: GAAD nodes use PascalCase (Arn, UserName, RoleName),
	// CloudResource nodes use lowercase (arn) from JSON tags.
	//
	// Queries include the Terraform suffix to isolate from leftover infrastructure
	// in shared AWS accounts.
	testCases := []struct {
		name  string
		query string
	}{
		{
			name: "CreatePolicyVersion",
			query: fmt.Sprintf(`
				MATCH (user:User)-[r:IAM_CREATEPOLICYVERSION]->(policy:Resource)
				WHERE user.Arn CONTAINS 'vuln-iam-createpolicyversion-user-%s'
				AND NOT (user)-[:IAM_SETDEFAULTPOLICYVERSION]->(:Resource)
				RETURN user.Arn, count(distinct policy) as policy_count`, suffix),
		},
		{
			name: "SetDefaultPolicyVersion",
			query: fmt.Sprintf(`
				MATCH (user:User)-[:IAM_SETDEFAULTPOLICYVERSION]->(policy:Resource)
				WHERE user.Arn CONTAINS 'vuln-iam-setdefaultpolicyversion-user-%s'
				AND policy.arn CONTAINS 'vuln-iam-setdefaultpolicyversion-target-%s'
				RETURN user.Arn AS vulnerable_user, policy.arn AS target_policy`, suffix, suffix),
		},
		{
			name: "ec2:RunInstances",
			query: fmt.Sprintf(`
				MATCH (attacker:User)-[:IAM_PASSROLE]->(target_role:Role),
				      (attacker)-[:EC2_RUNINSTANCES]->(ec2_service)
				WHERE attacker.Arn CONTAINS 'vuln-ec2-passrole-attacker-%s'
				AND target_role.Arn CONTAINS 'vuln-ec2-passrole-target-role-%s'
				RETURN attacker.Arn, target_role.Arn`, suffix, suffix),
		},
		{
			name: "iam:AddUserToGroup",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[r:IAM_ADDUSERTOGROUP]->(adminGroup)
				WHERE attacker.Arn CONTAINS 'vuln-iam-add-user-to-group-attacker-%s'
				AND adminGroup.Arn CONTAINS 'vuln-iam-add-user-to-group-admin-group-%s'
				RETURN attacker.RoleName AS AttackerRole, adminGroup.Arn AS AdminGroup`, suffix, suffix),
		},
		{
			name: "iam:CreateAccessKey",
			query: fmt.Sprintf(`
				MATCH (attacker:User)-[:IAM_CREATEACCESSKEY]->(target:User)
				WHERE attacker.Arn CONTAINS 'vuln-iam-create-access-key-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-create-access-key-target-%s'
				RETURN attacker.UserName AS AttackerUser, target.UserName AS TargetUser`, suffix, suffix),
		},
		{
			name: "iam:CreateLoginProfile",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_CREATELOGINPROFILE]->(target:User)
				WHERE attacker.Arn CONTAINS 'vuln-iam-create-login-profile-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-create-login-profile-target-%s'
				RETURN attacker.RoleName AS AttackerRole, target.UserName AS TargetUser`, suffix, suffix),
		},
		{
			name: "iam:UpdateLoginProfile",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_UPDATELOGINPROFILE]->(target:User)
				WHERE attacker.Arn CONTAINS 'vuln-iam-update-login-profile-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-iam-update-login-profile-target-%s'
				RETURN attacker.RoleName AS AttackerRole, target.UserName AS TargetUser`, suffix, suffix),
		},
		{
			name: "iam:AttachUserPolicy",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_ATTACHUSERPOLICY]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-attach-user-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-attach-user-policy-target-%s'
				RETURN attacker.RoleName AS AttackerRole, target.Arn AS Target`, suffix, suffix),
		},
		{
			name: "iam:AttachGroupPolicy",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_ATTACHGROUPPOLICY]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-attach-group-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-attach-group-policy-group-%s'
				RETURN attacker.RoleName AS AttackerRole, target.Arn AS TargetGroup`, suffix, suffix),
		},
		{
			name: "iam:AttachRolePolicy",
			query: fmt.Sprintf(`
				MATCH (target:Role)<-[:IAM_ATTACHROLEPOLICY]-(attacker)-[:STS_ASSUMEROLE]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-attach-role-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-attach-role-policy-target-%s'
				RETURN attacker.Arn AS AttackerRole, target.Arn AS TargetRole`, suffix, suffix),
		},
		{
			name: "iam:PutUserPolicy",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_PUTUSERPOLICY]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-put-user-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-put-user-policy-target-%s'
				RETURN attacker.RoleName AS AttackerRole, target.Arn AS TargetUser`, suffix, suffix),
		},
		{
			name: "iam:PutGroupPolicy",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_PUTGROUPPOLICY]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-put-group-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-put-group-policy-group-%s'
				RETURN attacker.RoleName AS AttackerRole, target.Arn AS TargetGroup`, suffix, suffix),
		},
		{
			name: "iam:PutRolePolicy",
			query: fmt.Sprintf(`
				MATCH (target:Role)<-[:IAM_PUTROLEPOLICY]-(attacker)-[:STS_ASSUMEROLE]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-put-role-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-put-role-policy-target-%s'
				RETURN attacker.Arn AS AttackerRole, target.Arn AS TargetRole`, suffix, suffix),
		},
		{
			name: "iam:UpdateAssumeRolePolicy",
			// Note: We only check IAM_UPDATEASSUMEROLEPOLICY (not STS_ASSUMEROLE)
			// because the target role's trust policy currently only allows
			// ec2.amazonaws.com. The privesc path works because the attacker
			// can modify the trust policy to add themselves, then assume it.
			// The enrichment query (method_13) correctly detects this pattern
			// without requiring a pre-existing STS_ASSUMEROLE edge.
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_UPDATEASSUMEROLEPOLICY]->(target)
				WHERE attacker.Arn CONTAINS 'vuln-iam-update-assume-role-policy-attacker-%s'
				AND target.Arn CONTAINS 'vuln-iam-update-assume-role-policy-target-%s'
				RETURN attacker.RoleName AS AttackerRole, target.Arn AS TargetArn`, suffix, suffix),
		},
		{
			name: "lambda:CreateFunction",
			query: fmt.Sprintf(`
				MATCH (user:User)-[:IAM_PASSROLE]->(role:Role),
				      (user)-[:LAMBDA_CREATEFUNCTION]->(lambdaService),
				      (user)-[:LAMBDA_INVOKEFUNCTION]->(lambdaService2)
				WHERE user.Arn CONTAINS 'vuln-lambda-createfunction-user-%s'
				AND role.Arn CONTAINS 'vuln-lambda-createfunction-privileged-role-%s'
				RETURN DISTINCT user.UserName AS AttackerUser, role.RoleName AS PrivilegedRole`, suffix, suffix),
		},
		{
			name: "cloudformation:CreateStack",
			query: fmt.Sprintf(`
				MATCH (attacker:Role)-[:IAM_PASSROLE]->(target:Role)
				WHERE attacker.RoleName CONTAINS 'vuln-cloudformation-createstack-attacker-%s'
				AND target.RoleName CONTAINS 'vuln-cloudformation-createstack-target-%s'
				WITH attacker, target
				MATCH (attacker)-[:CLOUDFORMATION_CREATESTACK]->(cfService)
				RETURN attacker.RoleName AS AttackerRole, target.RoleName AS TargetRole`, suffix, suffix),
		},
		{
			name: "ecs:RegisterTaskDefinition and ecs:RunTask",
			query: fmt.Sprintf(`
				MATCH (attacker:User)-[:IAM_PASSROLE]->(target:Role),
				      (attacker)-[:ECS_REGISTERTASKDEFINITION]->(),
				      (attacker)-[:ECS_RUNTASK]->()
				WHERE attacker.Arn CONTAINS 'vuln-ecs-registertaskdefinition-attacker-%s'
				AND target.Arn CONTAINS 'vuln-ecs-registertaskdefinition-task-role-%s'
				RETURN attacker.Arn AS AttackerUser, target.Arn AS PrivilegedRole
				LIMIT 1`, suffix, suffix),
		},
		{
			name: "lambda:CreateEventSourceMapping",
			query: fmt.Sprintf(`
				MATCH (attacker:User)-[:IAM_PASSROLE]->(privilegedRole:Role),
				      (attacker)-[:LAMBDA_CREATEFUNCTION]->()
				WHERE attacker.UserName CONTAINS 'vuln-lambda-eventsourcemapping-user-%s'
				AND privilegedRole.RoleName CONTAINS 'vuln-lambda-eventsourcemapping-privileged-role-%s'
				RETURN attacker.UserName AS AttackerUser, privilegedRole.RoleName AS PrivilegedRole`, suffix, suffix),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := adapter.Query(ctx, tc.query, nil)
			require.NoError(t, err, "query execution failed")
			assert.Len(t, result.Records, 1,
				"expected exactly 1 result for %s (got %d)", tc.name, len(result.Records))
		})
	}
}
