//go:build graph_test
// +build graph_test

package graph

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func getDriver(t *testing.T) neo4j.DriverWithContext {
	driver, err := neo4j.NewDriverWithContext(
		"bolt://localhost:7687",
		neo4j.BasicAuth("neo4j", "konstellation", ""),
	)

	if err != nil {
		t.Fatalf("Failed to create driver: %v", err)
	}

	return driver
}

func queryRunner(t *testing.T, query string) {
	// Create a database connection
	ctx := context.Background()
	driver := getDriver(t)
	defer driver.Close(ctx)

	// The query to execute

	result, err := neo4j.ExecuteQuery(ctx, driver,
		query,
		map[string]any{},
		neo4j.EagerResultTransformer,
		neo4j.ExecuteQueryWithDatabase("neo4j"))
	if err != nil {
		t.Error("Failed to execute query:", err)
	}

	// Validate the results
	if len(result.Records) != 1 {
		t.Errorf("Expected exactly 1 row, got %d", len(result.Records))
	}
}

type TestCase struct {
	name  string
	query string
}

func Test_Privesc(t *testing.T) {
	testCases := []TestCase{
		{
			name: "Test CreatePolicyVersion",
			query: `
	MATCH (user:Principal)-[r:` + "`iam:CreatePolicyVersion`" + `]->(policy:Resource)
	WHERE user.arn CONTAINS 'vuln-iam-createpolicyversion-user-'
	AND NOT (user)-[:` + "`iam:SetDefaultPolicyVersion`" + `]->(:Resource)
	RETURN user.arn, count(distinct policy) as policy_count
`,
		},
		{
			name: "SetDefaultPolicyVersion",
			query: `MATCH (user:Principal)-[:` + "`iam:SetDefaultPolicyVersion`" + `]->(policy:Resource)
WHERE 
  // Target the specific vulnerable user and policy from the terraform file
  user.arn CONTAINS 'vuln-iam-setdefaultpolicyversion-user' 
  AND policy.arn CONTAINS 'vuln-iam-setdefaultpolicyversion-target'
RETURN 
  user.arn AS vulnerable_user,
  policy.arn AS target_policy`,
		},
		{
			name: "ec2:RunInstances",
			query: `MATCH (attacker:User)-[r1:` + "`iam:PassRole`" + `]->(target_role:Role), (attacker)-[r2:` + "`ec2:RunInstances`" + `]->(ec2_service) 
  WHERE attacker.arn CONTAINS "vuln-ec2-passrole-attacker" 
    AND target_role.arn CONTAINS "vuln-ec2-passrole-target-role"
RETURN *`,
		},
		{
			name: "iam:AddUserToGroup",
			query: `MATCH (attacker:Role)-[r:` + "`iam:AddUserToGroup`" + `]->(adminGroup)
			WHERE attacker.arn contains "vuln-iam-add-user-to-group-attacker" and adminGroup.arn contains "vuln-iam-add-user-to-group-admin-group"
			RETURN attacker.identifier AS AttackerRole, adminGroup.identifier AS AdminGroup, type(r) AS Permission`,
		},
		{
			name: "iam:CreateAccessKey",
			query: `MATCH (attacker:User)-[r:` + "`iam:CreateAccessKey`" + `]->(target:User) 
			WHERE attacker.arn CONTAINS "vuln-iam-create-access-key-attacker" 
			AND target.arn CONTAINS "vuln-iam-create-access-key-target" 
			RETURN attacker.userName AS AttackerUser, target.userName AS TargetUser, type(r) AS Permission`,
		},
		{
			name: "iam:CreateLoginProfile",
			query: `MATCH (attacker:Role)-[r:` + "`iam:CreateLoginProfile`" + `]->(target:User) 
			WHERE attacker.arn CONTAINS "vuln-iam-create-login-profile-attacker" 
			AND target.arn CONTAINS "vuln-iam-create-login-profile-target" 
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetUser, type(r) AS Permission`,
		},
		{
			name: "iam:UpdateLoginProfile",
			query: `MATCH (attacker:Role)-[r:` + "`iam:UpdateLoginProfile`" + `]->(target:User) 
			WHERE attacker.arn CONTAINS "vuln-iam-update-login-profile-attacker" 
			AND target.arn CONTAINS "vuln-iam-iam-update-login-profile-target" 
			AND r.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetUser, type(r) AS Permission`,
		},
		{
			name: "iam:AttachUserPolicy",
			query: `MATCH (attacker:Role)-[r:` + "`iam:AttachUserPolicy`" + `]->(target) 
			WHERE attacker.arn CONTAINS "vuln-iam-attach-user-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-attach-user-policy-target" 
			AND r.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetUser, type(r) AS Permission`,
		},
		{
			name: "iam:AttachGroupPolicy",
			query: `MATCH (attacker:Role)-[r:` + "`iam:AttachGroupPolicy`" + `]->(target) 
			WHERE attacker.arn CONTAINS "vuln-iam-attach-group-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-attach-group-policy-group" 
			AND r.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetGroup, type(r) AS Permission`,
		},
		{
			name: "iam:AttachRolePolicy",
			query: `MATCH (target:Role)<-[r:` + "`iam:AttachRolePolicy`" + `]-(attacker)-[assume:` + "`sts:AssumeRole`" + `]->(target)
			WHERE attacker.arn CONTAINS "vuln-iam-attach-role-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-attach-role-policy-target"
			AND r.Allowed = true
			AND assume.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetRole, type(r) AS Permission, type(assume) AS AssumePermission`,
		},
		{
			name: "iam:PutUserPolicy",
			query: `MATCH (attacker:Role)-[r:` + "`iam:PutUserPolicy`" + `]->(target)
			WHERE attacker.arn CONTAINS "vuln-iam-put-user-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-put-user-policy-target" 
			AND r.Allowed = true
			AND "AWS::IAM::User" IN labels(target)
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetUser, type(r) AS Permission`,
		},
		{
			name: "iam:PutGroupPolicy",
			query: `MATCH (attacker:Role)-[r:` + "`iam:PutGroupPolicy`" + `]->(target) 
			WHERE attacker.arn CONTAINS "vuln-iam-put-group-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-put-group-policy-group" 
			AND r.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetGroup, type(r) AS Permission`,
		},
		{
			name: "iam:PutRolePolicy",
			query: `MATCH (target:Role)<-[r:` + "`iam:PutRolePolicy`" + `]-(attacker)-[assume:` + "`sts:AssumeRole`" + `]->(target)
			WHERE attacker.arn CONTAINS "vuln-iam-put-role-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-put-role-policy-target"
			AND r.Allowed = true
			AND assume.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetRole, type(r) AS Permission, type(assume) AS AssumePermission`,
		},
		{
			name: "iam:UpdateAssumeRolePolicy",
			query: `MATCH (attacker:Role)-[r:` + "`iam:UpdateAssumeRolePolicy`" + `]->(target:Role), (attacker)-[assume:` + "`sts:AssumeRole`" + `]->(target)
			WHERE attacker.arn CONTAINS "vuln-iam-update-assume-role-policy-attacker" 
			AND target.arn CONTAINS "vuln-iam-update-assume-role-policy-target"
			AND r.Allowed = true
			AND assume.Allowed = true
			RETURN attacker.identifier AS AttackerRole, target.identifier AS TargetRole, type(r) AS Permission, type(assume) AS AssumePermission`,
		},
		{
			name: "lambda:CreateFunction",
			query: `MATCH (user:User)-[passRole:` + "`iam:PassRole`" + `]->(role:Role), (user)-[createFunc:` + "`lambda:CreateFunction`" + `]->(lambdaService), (user)-[invokeFunc:` + "`lambda:InvokeFunction`" + `]->(lambdaService)
			WHERE user.arn CONTAINS "vuln-lambda-createfunction-user" 
			AND role.arn CONTAINS "vuln-lambda-createfunction-privileged-role"
			AND passRole.Allowed = true
			AND createFunc.Allowed = true
			AND invokeFunc.Allowed = true
			// This test validates the complete lambda:CreateFunction privilege escalation attack path.
			// The attack requires all three permissions: iam:PassRole, lambda:CreateFunction, and lambda:InvokeFunction.
			// All three relationships should be present for a complete attack scenario.
			RETURN user.userName AS AttackerUser, role.roleName AS PrivilegedRole, 
			       type(passRole) AS PassRolePermission, 
			       type(createFunc) AS CreateFunctionPermission,
			       type(invokeFunc) AS InvokeFunctionPermission`,
		},
		{
			name: "cloudformation:CreateStack",
			query: `MATCH (attacker:Role)-[passRole:` + "`iam:PassRole`" + `]->(target:Role)
			WHERE attacker.roleName CONTAINS "vuln-cloudformation-createstack-attacker" 
			AND target.roleName CONTAINS "vuln-cloudformation-createstack-target"
			AND target.assumeRolePolicyDoc CONTAINS "cloudformation.amazonaws.com"
			WITH attacker, target, passRole
			MATCH (attacker)-[createStack:` + "`cloudformation:CreateStack`" + `]->(cfService)
			WHERE createStack.Allowed = true
			// This test validates the complete cloudformation:CreateStack privilege escalation attack path.
			// The attack requires both iam:PassRole permission to a role that trusts CloudFormation and cloudformation:CreateStack permission.
			// The target role must trust cloudformation.amazonaws.com in its assume role policy to be usable in this attack.
			RETURN attacker.roleName as AttackerRole, 
			       target.roleName as TargetRole,
			       passRole.Allowed as CanPassRole,
			       createStack.Allowed as CanCreateStack`,
		},
		{
			name: "ecs:RegisterTaskDefinition and ecs:RunTask",
			query: `MATCH (attacker:User)-[passrole:` + "`iam:PassRole`" + `]->(target:Role), (attacker)-[ecs_register:` + "`ecs:RegisterTaskDefinition`" + `]->(), (attacker)-[ecs_run:` + "`ecs:RunTask`" + `]->() 
			WHERE attacker.identifier CONTAINS "vuln-ecs-registertaskdefinition-attacker" 
			AND target.identifier CONTAINS "vuln-ecs-registertaskdefinition" 
			AND target.assumeRolePolicyDoc CONTAINS "ecs-tasks.amazonaws.com"
			AND ecs_register.Allowed = true 
			AND ecs_run.Allowed = true 
			AND passrole.Allowed = true
			// This test validates the complete ECS privilege escalation attack path.
			// The attack requires all three permissions: iam:PassRole, ecs:RegisterTaskDefinition, and ecs:RunTask.
			// An attacker can register a malicious task definition with a privileged role and run it to steal credentials.
			// The target role must trust ecs-tasks.amazonaws.com in its assume role policy to be usable in this attack.
			RETURN attacker.identifier AS AttackerUser, 
			       target.identifier AS PrivilegedRole,
			       type(passrole) AS PassRolePermission, 
			       type(ecs_register) AS RegisterTaskDefPermission,
			       type(ecs_run) AS RunTaskPermission
			LIMIT 1`,
		},
		{
			name: "lambda:CreateEventSourceMapping",
			query: `MATCH (attacker:User)-[passRole:` + "`iam:PassRole`" + `]->(privilegedRole:Role), (attacker)-[createFunc:` + "`lambda:CreateFunction`" + `]->()
			WHERE attacker.userName CONTAINS "vuln-lambda-eventsourcemapping-user" 
			AND privilegedRole.roleName CONTAINS "vuln-lambda-eventsourcemapping-privileged-role"
			AND privilegedRole.admin = true
			AND privilegedRole.assumeRolePolicyDoc CONTAINS "lambda.amazonaws.com"
			AND passRole.Allowed = true
			AND createFunc.Allowed = true
			// This test validates the Lambda Event Source Mapping privilege escalation attack path.
			// The attack requires iam:PassRole to a privileged role and lambda:CreateFunction permission.
			// An attacker can create a Lambda function with privilege escalation code, pass a privileged role to it,
			// create an event source mapping to a DynamoDB stream, then trigger execution by updating the DynamoDB table.
			// The privileged role must trust lambda.amazonaws.com and have admin privileges for this attack to be effective.
			RETURN attacker.userName AS AttackerUser, 
			       privilegedRole.roleName AS PrivilegedRole,
			       privilegedRole.admin AS IsAdmin,
			       type(passRole) AS PassRolePermission, 
			       type(createFunc) AS CreateFunctionPermission`,
		},
		{
			name: "lambda:UpdateFunctionConfiguration PrivEsc",
			query: `
MATCH (u:User)-[:` + "`lambda:UpdateFunctionConfiguration`" + `]->(f:LambdaFunction)
WHERE u.name STARTS WITH 'vuln-lambda-updatefunctioncode-user'
  AND f.name STARTS WITH 'vuln-lambda-updatefunctioncode-target-function'
WITH u, f
MATCH (f)-[:` + "`lambda:UpdateFunctionConfiguration`" + `|:` + "`lambda:UpdateFunctionCode`" + `]->(r:Role)
WHERE r.name STARTS WITH 'vuln-lambda-updatefunctioncode-new-role'
WITH u, f, r
MATCH (r)-[:` + "`sts:AssumeRole`" + `]->(admin:Role)
WHERE admin.name STARTS WITH 'vuln-lambda-updatefunctioncode-admin-role'
RETURN u, f, r, admin
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			queryRunner(t, tc.query)
		})
	}

}
