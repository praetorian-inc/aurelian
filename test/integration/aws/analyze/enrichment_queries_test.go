//go:build integration

package analyze

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAdapter creates a Neo4j adapter for the shared test container.
func newAdapter(t *testing.T) *adapters.Neo4jAdapter {
	t.Helper()
	require.NotEmpty(t, sharedNeo4jBoltURL, "shared Neo4j container not available")
	cfg := graph.NewConfig(sharedNeo4jBoltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	return adapter
}

// execCypher runs a Cypher statement and returns the query result.
func execCypher(t *testing.T, ctx context.Context, adapter *adapters.Neo4jAdapter, cypher string) *graph.QueryResult {
	t.Helper()
	result, err := adapter.Query(ctx, cypher, nil)
	require.NoError(t, err, "failed to execute cypher: %s", cypher)
	return result
}

// ---------------------------------------------------------------------------
// General Enrichment Tests
// ---------------------------------------------------------------------------

func TestEnrichment_Accounts(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// Create 2 Principal nodes with AWS resource types
	execCypher(t, ctx, adapter, `
		CREATE (u:Principal {Arn: 'arn:aws:iam::111111111111:user/acct-user', _resourceType: 'AWS::IAM::User', UserName: 'acct-user'})
		CREATE (r:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/acct-role', _resourceType: 'AWS::IAM::Role', RoleName: 'acct-role'})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	// Verify both principals have _enriched = true
	result := execCypher(t, ctx, adapter, `
		MATCH (n:Principal)
		WHERE n._enriched = true
		RETURN n.Arn AS arn ORDER BY arn
	`)
	require.Len(t, result.Records, 2, "expected 2 enriched principals")
	assert.Equal(t, "arn:aws:iam::111111111111:role/acct-role", result.Records[0]["arn"])
	assert.Equal(t, "arn:aws:iam::111111111111:user/acct-user", result.Records[1]["arn"])
}

func TestEnrichment_ExtractRoleTrustRelationships(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	principalArn := "arn:aws:iam::111111111111:user/trust-user"
	trustDoc := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}`, principalArn)

	execCypher(t, ctx, adapter, fmt.Sprintf(`
		CREATE (role:Role:Principal {Arn: 'arn:aws:iam::111111111111:role/trust-role', RoleName: 'trust-role', AssumeRolePolicyDocument: '%s'})
		CREATE (user:Principal {Arn: '%s', UserName: 'trust-user'})
	`, trustDoc, principalArn))

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (p:Principal)-[r:CAN_ASSUME]->(role:Role)
		RETURN p.Arn AS principal_arn, role.Arn AS role_arn
	`)
	require.GreaterOrEqual(t, len(result.Records), 1, "expected at least 1 CAN_ASSUME relationship")
	assert.Equal(t, principalArn, result.Records[0]["principal_arn"])
	assert.Equal(t, "arn:aws:iam::111111111111:role/trust-role", result.Records[0]["role_arn"])
}

func TestEnrichment_ExtractRoleTrustedServices(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	execCypher(t, ctx, adapter, `
		CREATE (role:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/svc-trust-role',
			RoleName: 'svc-trust-role',
			trusted_services: ['lambda.amazonaws.com', 'ec2.amazonaws.com']
		})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (sp:ServicePrincipal)-[:CAN_ASSUME]->(role:Role)
		WHERE role.Arn = 'arn:aws:iam::111111111111:role/svc-trust-role'
		RETURN sp.service AS service ORDER BY service
	`)
	require.Len(t, result.Records, 2, "expected 2 ServicePrincipal CAN_ASSUME relationships")
	assert.Equal(t, "ec2.amazonaws.com", result.Records[0]["service"])
	assert.Equal(t, "lambda.amazonaws.com", result.Records[1]["service"])
}

func TestEnrichment_ResourceToRole(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	roleArn := "arn:aws:iam::111111111111:role/instance-role"
	execCypher(t, ctx, adapter, fmt.Sprintf(`
		CREATE (role:Role:Principal {
			Arn: '%s',
			RoleName: 'instance-role',
			InstanceProfileList: ['ip-12345']
		})
		CREATE (resource:Resource {
			Arn: 'arn:aws:ec2:us-east-1:111111111111:instance/i-abc123',
			_resourceType: 'AWS::EC2::Instance',
			IamInstanceProfile: 'ip-12345'
		})
	`, roleArn))

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (resource:Resource)-[:HAS_ROLE]->(role:Role)
		RETURN resource.Arn AS resource_arn, role.Arn AS role_arn
	`)
	require.Len(t, result.Records, 1, "expected 1 HAS_ROLE relationship")
	assert.Equal(t, "arn:aws:ec2:us-east-1:111111111111:instance/i-abc123", result.Records[0]["resource_arn"])
	assert.Equal(t, roleArn, result.Records[0]["role_arn"])
}

func TestEnrichment_SetAdminAdministratorAccess(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	execCypher(t, ctx, adapter, `
		CREATE (admin:Principal {
			Arn: 'arn:aws:iam::111111111111:user/admin-user',
			UserName: 'admin-user',
			_resourceType: 'AWS::IAM::User',
			AttachedManagedPolicies: ['arn:aws:iam::aws:policy/AdministratorAccess']
		})
		CREATE (regular:Principal {
			Arn: 'arn:aws:iam::111111111111:user/regular-user',
			UserName: 'regular-user',
			_resourceType: 'AWS::IAM::User',
			AttachedManagedPolicies: ['arn:aws:iam::aws:policy/ReadOnlyAccess']
		})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	// Verify admin-user has _is_admin = true
	result := execCypher(t, ctx, adapter, `
		MATCH (p:Principal {Arn: 'arn:aws:iam::111111111111:user/admin-user'})
		RETURN p._is_admin AS is_admin, p._admin_reason AS reason
	`)
	require.Len(t, result.Records, 1)
	assert.Equal(t, true, result.Records[0]["is_admin"])
	assert.Equal(t, "AdministratorAccess managed policy", result.Records[0]["reason"])

	// Verify regular-user does NOT have _is_admin
	result = execCypher(t, ctx, adapter, `
		MATCH (p:Principal {Arn: 'arn:aws:iam::111111111111:user/regular-user'})
		RETURN p._is_admin AS is_admin
	`)
	require.Len(t, result.Records, 1)
	assert.Nil(t, result.Records[0]["is_admin"], "regular-user should not have _is_admin")
}

func TestEnrichment_SetAdminInlineWildcard(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// The query matches: (p:Principal)-[perm]->(resource) WHERE perm.action = '*' AND type(perm) = 'IAM_WILDCARD'
	execCypher(t, ctx, adapter, `
		CREATE (p:Principal {Arn: 'arn:aws:iam::111111111111:user/wildcard-user', UserName: 'wildcard-user', _resourceType: 'AWS::IAM::User'})
		CREATE (r:Resource {Arn: 'arn:aws:iam::111111111111:*'})
		CREATE (p)-[:IAM_WILDCARD {action: '*'}]->(r)
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (p:Principal {Arn: 'arn:aws:iam::111111111111:user/wildcard-user'})
		RETURN p._is_admin AS is_admin, p._admin_reason AS reason
	`)
	require.Len(t, result.Records, 1)
	assert.Equal(t, true, result.Records[0]["is_admin"])
	assert.Equal(t, "Inline wildcard policy (*:*)", result.Records[0]["reason"])
}

func TestEnrichment_SetPrivilegedAccess(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	execCypher(t, ctx, adapter, `
		CREATE (p:Principal {Arn: 'arn:aws:iam::111111111111:user/priv-user', UserName: 'priv-user', _resourceType: 'AWS::IAM::User'})
		CREATE (r:Resource {Arn: 'arn:aws:iam::111111111111:role/some-role'})
		CREATE (p)-[:IAM_PASSROLE]->(r)
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (p:Principal {Arn: 'arn:aws:iam::111111111111:user/priv-user'})
		RETURN p._is_privileged AS is_priv
	`)
	require.Len(t, result.Records, 1)
	assert.Equal(t, true, result.Records[0]["is_priv"])
}

func TestEnrichment_SetSSMEnabledRoles(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	execCypher(t, ctx, adapter, `
		CREATE (ssm:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/ssm-role',
			RoleName: 'ssm-role',
			trusted_services: ['ssm.amazonaws.com', 'ec2.amazonaws.com']
		})
		CREATE (nossm:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/nossm-role',
			RoleName: 'nossm-role',
			trusted_services: ['lambda.amazonaws.com']
		})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	// ssm-role should have _ssm_enabled = true
	result := execCypher(t, ctx, adapter, `
		MATCH (r:Role {Arn: 'arn:aws:iam::111111111111:role/ssm-role'})
		RETURN r._ssm_enabled AS ssm_enabled
	`)
	require.Len(t, result.Records, 1)
	assert.Equal(t, true, result.Records[0]["ssm_enabled"])

	// nossm-role should NOT have _ssm_enabled
	result = execCypher(t, ctx, adapter, `
		MATCH (r:Role {Arn: 'arn:aws:iam::111111111111:role/nossm-role'})
		RETURN r._ssm_enabled AS ssm_enabled
	`)
	require.Len(t, result.Records, 1)
	assert.Nil(t, result.Records[0]["ssm_enabled"], "nossm-role should not have _ssm_enabled")
}

func TestEnrichment_LinkPoliciesToRoles(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	execCypher(t, ctx, adapter, `
		CREATE (p:Principal {
			Arn: 'arn:aws:iam::111111111111:role/policy-role',
			RoleName: 'policy-role',
			_resourceType: 'AWS::IAM::Role',
			AttachedManagedPolicies: ['arn:aws:iam::aws:policy/ReadOnlyAccess', 'arn:aws:iam::aws:policy/IAMFullAccess', 'arn:aws:iam::aws:policy/S3FullAccess']
		})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (p:Principal {Arn: 'arn:aws:iam::111111111111:role/policy-role'})
		RETURN p._policy_count AS policy_count
	`)
	require.Len(t, result.Records, 1)
	// size() returns int64 in Neo4j
	assert.Equal(t, int64(3), result.Records[0]["policy_count"])
}

// ---------------------------------------------------------------------------
// Privilege Escalation Method Tests (Table-Driven)
// ---------------------------------------------------------------------------

func TestEnrichment_PrivescMethods(t *testing.T) {
	// Each test case defines: a name, Cypher to create the test graph, Cypher to verify
	// the expected CAN_PRIVESC relationship, and the expected method string.
	//
	// The queries fall into patterns:
	//   (A) Direct perm -> creates CAN_PRIVESC to ALL other Principals (victim.Arn <> attacker.Arn)
	//   (B) PassRole + service action -> creates CAN_PRIVESC to the service_resource
	//   (C) Compound patterns (31, 38, 39, 41, 42)
	testCases := []struct {
		name         string
		setupCypher  string
		verifyCypher string
	}{
		{
			name: "method_01_CreatePolicyVersion",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m01', UserName: 'attacker-m01'})
				CREATE (t:Resource {Arn: 'arn:aws:iam::111111111111:policy/target-m01'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m01', RoleName: 'victim-m01'})
				CREATE (a)-[:IAM_CREATEPOLICYVERSION]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m01'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m01'
				AND pe.method = 'iam:CreatePolicyVersion'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_02_SetDefaultPolicyVersion",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m02', UserName: 'attacker-m02'})
				CREATE (t:Resource {Arn: 'arn:aws:iam::111111111111:policy/target-m02'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m02', RoleName: 'victim-m02'})
				CREATE (a)-[:IAM_SETDEFAULTPOLICYVERSION]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m02'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m02'
				AND pe.method = 'iam:SetDefaultPolicyVersion'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_03_CreateAccessKey",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m03', UserName: 'attacker-m03'})
				CREATE (t:Principal:User {Arn: 'arn:aws:iam::111111111111:user/target-m03', UserName: 'target-m03'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m03', RoleName: 'victim-m03'})
				CREATE (a)-[:IAM_CREATEACCESSKEY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m03'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m03'
				AND pe.method = 'iam:CreateAccessKey'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_04_CreateLoginProfile",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m04', UserName: 'attacker-m04'})
				CREATE (t:Principal:User {Arn: 'arn:aws:iam::111111111111:user/target-m04', UserName: 'target-m04'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m04', RoleName: 'victim-m04'})
				CREATE (a)-[:IAM_CREATELOGINPROFILE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m04'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m04'
				AND pe.method = 'iam:CreateLoginProfile'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_05_UpdateLoginProfile",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m05', UserName: 'attacker-m05'})
				CREATE (t:Principal:User {Arn: 'arn:aws:iam::111111111111:user/target-m05', UserName: 'target-m05'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m05', RoleName: 'victim-m05'})
				CREATE (a)-[:IAM_UPDATELOGINPROFILE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m05'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m05'
				AND pe.method = 'iam:UpdateLoginProfile'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_06_AttachUserPolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m06', UserName: 'attacker-m06'})
				CREATE (t:Principal:User {Arn: 'arn:aws:iam::111111111111:user/target-m06', UserName: 'target-m06'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m06', RoleName: 'victim-m06'})
				CREATE (a)-[:IAM_ATTACHUSERPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m06'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m06'
				AND pe.method = 'iam:AttachUserPolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_07_AttachGroupPolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m07', UserName: 'attacker-m07'})
				CREATE (t:Principal:Group {Arn: 'arn:aws:iam::111111111111:group/target-m07', GroupName: 'target-m07'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m07', RoleName: 'victim-m07'})
				CREATE (a)-[:IAM_ATTACHGROUPPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m07'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m07'
				AND pe.method = 'iam:AttachGroupPolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_08_AttachRolePolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m08', UserName: 'attacker-m08'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m08', RoleName: 'target-m08'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m08', RoleName: 'victim-m08'})
				CREATE (a)-[:IAM_ATTACHROLEPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m08'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m08'
				AND pe.method = 'iam:AttachRolePolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_09_PutUserPolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m09', UserName: 'attacker-m09'})
				CREATE (t:Principal:User {Arn: 'arn:aws:iam::111111111111:user/target-m09', UserName: 'target-m09'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m09', RoleName: 'victim-m09'})
				CREATE (a)-[:IAM_PUTUSERPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m09'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m09'
				AND pe.method = 'iam:PutUserPolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_10_PutGroupPolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m10', UserName: 'attacker-m10'})
				CREATE (t:Principal:Group {Arn: 'arn:aws:iam::111111111111:group/target-m10', GroupName: 'target-m10'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m10', RoleName: 'victim-m10'})
				CREATE (a)-[:IAM_PUTGROUPPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m10'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m10'
				AND pe.method = 'iam:PutGroupPolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_11_PutRolePolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m11', UserName: 'attacker-m11'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m11', RoleName: 'target-m11'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m11', RoleName: 'victim-m11'})
				CREATE (a)-[:IAM_PUTROLEPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m11'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m11'
				AND pe.method = 'iam:PutRolePolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_12_AddUserToGroup",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m12', UserName: 'attacker-m12'})
				CREATE (t:Principal:Group {Arn: 'arn:aws:iam::111111111111:group/target-m12', GroupName: 'target-m12'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m12', RoleName: 'victim-m12'})
				CREATE (a)-[:IAM_ADDUSERTOGROUP]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m12'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m12'
				AND pe.method = 'iam:AddUserToGroup'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_13_UpdateAssumeRolePolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m13', UserName: 'attacker-m13'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m13', RoleName: 'target-m13'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m13', RoleName: 'victim-m13'})
				CREATE (a)-[:IAM_UPDATEASSUMEROLEPOLICY]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m13'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m13'
				AND pe.method = 'iam:UpdateAssumeRolePolicy'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		// PassRole + Service methods (14-19)
		{
			name: "method_14_PassRole_Lambda",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m14', UserName: 'attacker-m14'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m14', RoleName: 'target-m14'})
				CREATE (s:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:function:svc-m14'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:LAMBDA_CREATEFUNCTION]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m14'
				AND s.Arn = 'arn:aws:lambda:us-east-1:111111111111:function:svc-m14'
				AND pe.method = 'iam:PassRole + lambda:CreateFunction'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_15_PassRole_EC2",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m15', UserName: 'attacker-m15'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m15', RoleName: 'target-m15'})
				CREATE (s:Resource {Arn: 'arn:aws:ec2:us-east-1:111111111111:instance/svc-m15'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:EC2_RUNINSTANCES]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m15'
				AND s.Arn = 'arn:aws:ec2:us-east-1:111111111111:instance/svc-m15'
				AND pe.method = 'iam:PassRole + ec2:RunInstances'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_16_PassRole_CloudFormation",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m16', UserName: 'attacker-m16'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m16', RoleName: 'target-m16'})
				CREATE (s:Resource {Arn: 'arn:aws:cloudformation:us-east-1:111111111111:stack/svc-m16'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:CLOUDFORMATION_CREATESTACK]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m16'
				AND s.Arn = 'arn:aws:cloudformation:us-east-1:111111111111:stack/svc-m16'
				AND pe.method = 'iam:PassRole + cloudformation:CreateStack'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_17_PassRole_DataPipeline",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m17', UserName: 'attacker-m17'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m17', RoleName: 'target-m17'})
				CREATE (s:Resource {Arn: 'arn:aws:datapipeline:us-east-1:111111111111:pipeline/svc-m17'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:DATAPIPELINE_CREATEPIPELINE]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m17'
				AND s.Arn = 'arn:aws:datapipeline:us-east-1:111111111111:pipeline/svc-m17'
				AND pe.method = 'iam:PassRole + datapipeline:CreatePipeline'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_18_PassRole_Glue",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m18', UserName: 'attacker-m18'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m18', RoleName: 'target-m18'})
				CREATE (s:Resource {Arn: 'arn:aws:glue:us-east-1:111111111111:job/svc-m18'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:GLUE_CREATEJOB]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m18'
				AND s.Arn = 'arn:aws:glue:us-east-1:111111111111:job/svc-m18'
				AND pe.method = 'iam:PassRole + glue:CreateJob'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_19_PassRole_SageMaker",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m19', UserName: 'attacker-m19'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m19', RoleName: 'target-m19'})
				CREATE (s:Resource {Arn: 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/svc-m19'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:SAGEMAKER_CREATENOTEBOOKINSTANCE]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m19'
				AND s.Arn = 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/svc-m19'
				AND pe.method = 'iam:PassRole + sagemaker:CreateNotebookInstance'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		// Direct permission methods (20-28)
		{
			name: "method_20_LambdaUpdateFunctionCode",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m20', UserName: 'attacker-m20'})
				CREATE (t:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:function:target-m20'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m20', RoleName: 'victim-m20'})
				CREATE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m20'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m20'
				AND pe.method = 'lambda:UpdateFunctionCode'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_21_LambdaCreateEventSourceMapping",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m21', UserName: 'attacker-m21'})
				CREATE (t:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:event-source-mapping/target-m21'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m21', RoleName: 'victim-m21'})
				CREATE (a)-[:LAMBDA_CREATEEVENTSOURCEMAPPING]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m21'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m21'
				AND pe.method = 'lambda:CreateEventSourceMapping'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_22_STSAssumeRole",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m22', UserName: 'attacker-m22'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m22', RoleName: 'target-m22'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m22', RoleName: 'victim-m22'})
				CREATE (a)-[:STS_ASSUMEROLE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m22'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m22'
				AND pe.method = 'sts:AssumeRole'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_23_SSMSendCommand",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m23', UserName: 'attacker-m23'})
				CREATE (t:Resource {Arn: 'arn:aws:ec2:us-east-1:111111111111:instance/target-m23'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m23', RoleName: 'victim-m23'})
				CREATE (a)-[:SSM_SENDCOMMAND]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m23'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m23'
				AND pe.method = 'ssm:SendCommand'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_24_SSMStartSession",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m24', UserName: 'attacker-m24'})
				CREATE (t:Resource {Arn: 'arn:aws:ec2:us-east-1:111111111111:instance/target-m24'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m24', RoleName: 'victim-m24'})
				CREATE (a)-[:SSM_STARTSESSION]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m24'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m24'
				AND pe.method = 'ssm:StartSession'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_25_EC2SSMAssociation",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m25', UserName: 'attacker-m25'})
				CREATE (t:Resource {Arn: 'arn:aws:ec2:us-east-1:111111111111:instance/target-m25'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m25', RoleName: 'victim-m25'})
				CREATE (a)-[:SSM_CREATEASSOCIATION]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m25'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m25'
				AND pe.method = 'ssm:CreateAssociation'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_26_CodeStarCreateProject",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m26', UserName: 'attacker-m26'})
				CREATE (t:Resource {Arn: 'arn:aws:codestar:us-east-1:111111111111:project/target-m26'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m26', RoleName: 'victim-m26'})
				CREATE (a)-[:CODESTAR_CREATEPROJECT]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m26'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m26'
				AND pe.method = 'codestar:CreateProject'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_27_CodeBuildCreateProject",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m27', UserName: 'attacker-m27'})
				CREATE (t:Resource {Arn: 'arn:aws:codebuild:us-east-1:111111111111:project/target-m27'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m27', RoleName: 'victim-m27'})
				CREATE (a)-[:CODEBUILD_CREATEPROJECT]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m27'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m27'
				AND pe.method = 'codebuild:CreateProject'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_28_CreateServiceLinkedRole",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m28', UserName: 'attacker-m28'})
				CREATE (t:Resource {Arn: 'arn:aws:iam::111111111111:role/aws-service-role/target-m28'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m28', RoleName: 'victim-m28'})
				CREATE (a)-[:IAM_CREATESERVICELINKEDROLE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m28'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m28'
				AND pe.method = 'iam:CreateServiceLinkedRole'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		// New methods (29-42)
		{
			name: "method_29_GlueUpdateDevEndpoint",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m29', UserName: 'attacker-m29'})
				CREATE (t:Resource {Arn: 'arn:aws:glue:us-east-1:111111111111:devEndpoint/target-m29'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m29', RoleName: 'victim-m29'})
				CREATE (a)-[:GLUE_UPDATEDEVENDPOINT]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m29'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m29'
				AND pe.method = 'glue:UpdateDevEndpoint'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_30_PassRole_CloudFormation_UpdateStack",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m30', UserName: 'attacker-m30'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m30', RoleName: 'target-m30'})
				CREATE (s:Resource {Arn: 'arn:aws:cloudformation:us-east-1:111111111111:stack/svc-m30'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:CLOUDFORMATION_UPDATESTACK]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m30'
				AND s.Arn = 'arn:aws:cloudformation:us-east-1:111111111111:stack/svc-m30'
				AND pe.method = 'iam:PassRole + cloudformation:UpdateStack'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_31_PassRole_CloudFormation_ChangeSet",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m31', UserName: 'attacker-m31'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m31', RoleName: 'target-m31'})
				CREATE (s1:Resource {Arn: 'arn:aws:cloudformation:us-east-1:111111111111:changeset/svc-m31'})
				CREATE (s2:Resource {Arn: 'arn:aws:cloudformation:us-east-1:111111111111:exec/svc-m31'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:CLOUDFORMATION_CREATECHANGESET]->(s1)
				CREATE (a)-[:CLOUDFORMATION_EXECUTECHANGESET]->(s2)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m31'
				AND s.Arn = 'arn:aws:cloudformation:us-east-1:111111111111:changeset/svc-m31'
				AND pe.method = 'iam:PassRole + cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_32_PassRole_ECS_RunTask",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m32', UserName: 'attacker-m32'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m32', RoleName: 'target-m32'})
				CREATE (s:Resource {Arn: 'arn:aws:ecs:us-east-1:111111111111:task/svc-m32'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:ECS_RUNTASK]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m32'
				AND s.Arn = 'arn:aws:ecs:us-east-1:111111111111:task/svc-m32'
				AND pe.method = 'iam:PassRole + ecs:RunTask'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_33_CodeBuildStartBuild",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m33', UserName: 'attacker-m33'})
				CREATE (t:Resource {Arn: 'arn:aws:codebuild:us-east-1:111111111111:project/target-m33'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m33', RoleName: 'victim-m33'})
				CREATE (a)-[:CODEBUILD_STARTBUILD]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m33'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m33'
				AND pe.method = 'codebuild:StartBuild'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_34_PassRole_CodeBuildUpdateProject",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m34', UserName: 'attacker-m34'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m34', RoleName: 'target-m34'})
				CREATE (s:Resource {Arn: 'arn:aws:codebuild:us-east-1:111111111111:project/svc-m34'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:CODEBUILD_UPDATEPROJECT]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m34'
				AND s.Arn = 'arn:aws:codebuild:us-east-1:111111111111:project/svc-m34'
				AND pe.method = 'iam:PassRole + codebuild:UpdateProject'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_35_SageMakerPresignedUrl",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m35', UserName: 'attacker-m35'})
				CREATE (t:Resource {Arn: 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/target-m35'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m35', RoleName: 'victim-m35'})
				CREATE (a)-[:SAGEMAKER_CREATEPRESIGNEDNOTEBOOKINSTANCEURL]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m35'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m35'
				AND pe.method = 'sagemaker:CreatePresignedNotebookInstanceUrl'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_36_PassRole_SageMakerTrainingJob",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m36', UserName: 'attacker-m36'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m36', RoleName: 'target-m36'})
				CREATE (s:Resource {Arn: 'arn:aws:sagemaker:us-east-1:111111111111:training-job/svc-m36'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:SAGEMAKER_CREATETRAININGJOB]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m36'
				AND s.Arn = 'arn:aws:sagemaker:us-east-1:111111111111:training-job/svc-m36'
				AND pe.method = 'iam:PassRole + sagemaker:CreateTrainingJob'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_37_PassRole_SageMakerProcessingJob",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m37', UserName: 'attacker-m37'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m37', RoleName: 'target-m37'})
				CREATE (s:Resource {Arn: 'arn:aws:sagemaker:us-east-1:111111111111:processing-job/svc-m37'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:SAGEMAKER_CREATEPROCESSINGJOB]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m37'
				AND s.Arn = 'arn:aws:sagemaker:us-east-1:111111111111:processing-job/svc-m37'
				AND pe.method = 'iam:PassRole + sagemaker:CreateProcessingJob'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_38_PassRole_AutoScalingLaunchTemplate",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m38', UserName: 'attacker-m38'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m38', RoleName: 'target-m38'})
				CREATE (lt:Resource {Arn: 'arn:aws:ec2:us-east-1:111111111111:launch-template/svc-m38'})
				CREATE (asg:Resource {Arn: 'arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup/asg-m38'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:EC2_CREATELAUNCHTEMPLATE]->(lt)
				CREATE (a)-[:AUTOSCALING_CREATEAUTOSCALINGGROUP]->(asg)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m38'
				AND s.Arn = 'arn:aws:ec2:us-east-1:111111111111:launch-template/svc-m38'
				AND pe.method = 'iam:PassRole + ec2:CreateLaunchTemplate + autoscaling:CreateAutoScalingGroup'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			name: "method_39_LambdaUpdateCodeInvoke",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m39', UserName: 'attacker-m39'})
				CREATE (t:Resource {Arn: 'arn:aws:lambda:us-east-1:111111111111:function:target-m39'})
				CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/victim-m39', RoleName: 'victim-m39'})
				CREATE (a)-[:LAMBDA_UPDATEFUNCTIONCODE]->(t)
				CREATE (a)-[:LAMBDA_INVOKEFUNCTION]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m39'
				AND v.Arn = 'arn:aws:iam::111111111111:role/victim-m39'
				AND pe.method = 'lambda:UpdateFunctionCode + lambda:InvokeFunction'
				RETURN a.Arn AS attacker, v.Arn AS victim`,
		},
		{
			name: "method_40_PassRole_BedrockCreateCodeInterpreter",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m40', UserName: 'attacker-m40'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m40', RoleName: 'target-m40'})
				CREATE (s:Resource {Arn: 'arn:aws:bedrock:us-east-1:111111111111:code-interpreter/svc-m40'})
				CREATE (a)-[:IAM_PASSROLE]->(t)
				CREATE (a)-[:BEDROCK_AGENTCORE_CREATECODEINTERPRETER]->(s)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(s:Resource)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m40'
				AND s.Arn = 'arn:aws:bedrock:us-east-1:111111111111:code-interpreter/svc-m40'
				AND pe.method = 'iam:PassRole + bedrock-agentcore:CreateCodeInterpreter'
				RETURN a.Arn AS attacker, s.Arn AS service`,
		},
		{
			// Method 41: attacker can modify a role's policies AND PassRole to it
			// Query: MATCH (attacker)-[modify]->(target:Role) WHERE type(modify) IN [PUTROLEPOLICY, ATTACHROLEPOLICY]
			//        AND target.Arn <> attacker.Arn
			//        WITH attacker, target
			//        MATCH (attacker)-[passrole]->(target) WHERE type(passrole) = 'IAM_PASSROLE'
			name: "method_41_PassRoleModifyPolicy",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m41', UserName: 'attacker-m41'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m41', RoleName: 'target-m41'})
				CREATE (a)-[:IAM_PUTROLEPOLICY]->(t)
				CREATE (a)-[:IAM_PASSROLE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(t:Principal:Role)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m41'
				AND t.Arn = 'arn:aws:iam::111111111111:role/target-m41'
				AND pe.method = 'iam:PassRole + policy modification'
				RETURN a.Arn AS attacker, t.Arn AS target`,
		},
		{
			// Method 42: attacker can UpdateAssumeRolePolicy AND PassRole to a role
			// Query: MATCH (attacker)-[update]->(target:Role) WHERE type(update) = 'IAM_UPDATEASSUMEROLEPOLICY'
			//        AND target.Arn <> attacker.Arn
			//        WITH attacker, target
			//        MATCH (attacker)-[passrole]->(target) WHERE type(passrole) = 'IAM_PASSROLE'
			name: "method_42_UpdateAssumeRolePolicyPassRoleService",
			setupCypher: `
				CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/attacker-m42', UserName: 'attacker-m42'})
				CREATE (t:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/target-m42', RoleName: 'target-m42'})
				CREATE (a)-[:IAM_UPDATEASSUMEROLEPOLICY]->(t)
				CREATE (a)-[:IAM_PASSROLE]->(t)`,
			verifyCypher: `
				MATCH (a:Principal)-[pe:CAN_PRIVESC]->(t:Principal:Role)
				WHERE a.Arn = 'arn:aws:iam::111111111111:user/attacker-m42'
				AND t.Arn = 'arn:aws:iam::111111111111:role/target-m42'
				AND pe.method = 'iam:UpdateAssumeRolePolicy + iam:PassRole + service'
				RETURN a.Arn AS attacker, t.Arn AS target`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)

			adapter := newAdapter(t)
			defer adapter.Close()

			// Set up the graph state
			execCypher(t, ctx, adapter, tc.setupCypher)

			// Run all enrichment queries (includes privesc detection)
			err := queries.EnrichAWS(ctx, adapter)
			require.NoError(t, err, "EnrichAWS failed for %s", tc.name)

			// Verify the expected CAN_PRIVESC relationship was created
			result := execCypher(t, ctx, adapter, tc.verifyCypher)
			require.GreaterOrEqual(t, len(result.Records), 1,
				"expected at least 1 CAN_PRIVESC relationship for %s, got %d", tc.name, len(result.Records))

			// Verify specific ARN values in the first record
			record := result.Records[0]
			if attacker, ok := record["attacker"]; ok {
				assert.Contains(t, attacker, "attacker-", "attacker ARN should contain attacker identifier for %s", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Negative Tests
// ---------------------------------------------------------------------------

func TestEnrichment_PrivescNegative_NoRelationship(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// Create attacker and victim but NO permission relationship between them
	execCypher(t, ctx, adapter, `
		CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/no-perm-attacker', UserName: 'no-perm-attacker'})
		CREATE (v:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/no-perm-victim', RoleName: 'no-perm-victim'})
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	result := execCypher(t, ctx, adapter, `
		MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
		WHERE a.Arn = 'arn:aws:iam::111111111111:user/no-perm-attacker'
		AND v.Arn = 'arn:aws:iam::111111111111:role/no-perm-victim'
		RETURN count(pe) AS pe_count
	`)
	require.Len(t, result.Records, 1)
	peCount, ok := result.Records[0]["pe_count"].(int64)
	require.True(t, ok, "pe_count should be int64")
	assert.Equal(t, int64(0), peCount, "should have 0 CAN_PRIVESC without any permission relationships")
}

func TestEnrichment_PrivescNegative_SameArn(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// Create a single principal that has a permission on a resource, but it is
	// the ONLY principal in the graph. The privesc queries use
	// "WHERE victim.Arn <> attacker.Arn" so no self-loop should be created.
	execCypher(t, ctx, adapter, `
		CREATE (a:Principal:User {Arn: 'arn:aws:iam::111111111111:user/self-loop-user', UserName: 'self-loop-user'})
		CREATE (r:Resource {Arn: 'arn:aws:iam::111111111111:policy/some-policy'})
		CREATE (a)-[:IAM_CREATEPOLICYVERSION]->(r)
	`)

	err := queries.EnrichAWS(ctx, adapter)
	require.NoError(t, err)

	// There should be no CAN_PRIVESC where attacker == victim
	result := execCypher(t, ctx, adapter, `
		MATCH (a:Principal)-[pe:CAN_PRIVESC]->(v:Principal)
		WHERE a.Arn = v.Arn
		RETURN count(pe) AS self_loops
	`)
	require.Len(t, result.Records, 1)
	selfLoops, ok := result.Records[0]["self_loops"].(int64)
	require.True(t, ok, "self_loops should be int64")
	assert.Equal(t, int64(0), selfLoops, "should have no CAN_PRIVESC self-loops")
}

// ---------------------------------------------------------------------------
// Analysis Query Tests
// ---------------------------------------------------------------------------

func TestAnalysis_ExternalRoleTrust(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// Create a role with public trust ("*" in the document)
	// and another role without public trust
	execCypher(t, ctx, adapter, `
		CREATE (public_role:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/public-trust-role',
			RoleName: 'public-trust-role',
			AssumeRolePolicyDocument: '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}'
		})
		CREATE (private_role:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/private-trust-role',
			RoleName: 'private-trust-role',
			AssumeRolePolicyDocument: '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}'
		})
		CREATE (internal_role:Role:Principal {
			Arn: 'arn:aws:iam::111111111111:role/internal-role',
			RoleName: 'internal-role',
			AssumeRolePolicyDocument: '{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
		})
	`)

	// Run the specific analysis query
	result, err := queries.RunPlatformQuery(ctx, adapter, "aws/analysis/external_role_trust", nil)
	require.NoError(t, err)

	// The public-trust-role should appear (contains '"*"')
	// The private-trust-role should appear (contains ':root"')
	// The internal-role should NOT appear
	foundPublic := false
	foundPrivate := false
	foundInternal := false
	for _, record := range result.Records {
		arn, _ := record["role_arn"].(string)
		switch arn {
		case "arn:aws:iam::111111111111:role/public-trust-role":
			foundPublic = true
			assert.Equal(t, true, record["trusts_public"], "public-trust-role should have trusts_public=true")
		case "arn:aws:iam::111111111111:role/private-trust-role":
			foundPrivate = true
			assert.Equal(t, true, record["trusts_account_root"], "private-trust-role should have trusts_account_root=true")
		case "arn:aws:iam::111111111111:role/internal-role":
			foundInternal = true
		}
	}
	assert.True(t, foundPublic, "public-trust-role should be in external trust results")
	assert.True(t, foundPrivate, "private-trust-role should be in external trust results (contains :root\")")
	assert.False(t, foundInternal, "internal-role should NOT appear in external trust results")
}

func TestAnalysis_PrivescPaths(t *testing.T) {
	ctx := context.Background()
	testutil.ClearNeo4jDatabase(t, sharedNeo4jBoltURL)
	adapter := newAdapter(t)
	defer adapter.Close()

	// Create a chain: attacker -> intermediate -> admin
	// attacker is NOT admin, intermediate is NOT admin, target IS admin
	execCypher(t, ctx, adapter, `
		CREATE (attacker:Principal:User {Arn: 'arn:aws:iam::111111111111:user/chain-attacker', UserName: 'chain-attacker', _is_admin: false})
		CREATE (intermediate:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/chain-intermediate', RoleName: 'chain-intermediate', _is_admin: false})
		CREATE (admin:Principal:Role {Arn: 'arn:aws:iam::111111111111:role/chain-admin', RoleName: 'chain-admin', _is_admin: true})
		CREATE (attacker)-[:CAN_PRIVESC {method: 'test-method-1'}]->(intermediate)
		CREATE (intermediate)-[:CAN_PRIVESC {method: 'test-method-2'}]->(admin)
	`)

	result, err := queries.RunPlatformQuery(ctx, adapter, "aws/analysis/privesc_paths", nil)
	require.NoError(t, err)

	// We expect at least the 2-hop path: attacker -> intermediate -> admin
	// and the 1-hop path: intermediate -> admin
	foundTwoHop := false
	foundOneHop := false
	for _, record := range result.Records {
		attackerArn, _ := record["attacker_arn"].(string)
		targetArn, _ := record["target_arn"].(string)
		hopCount, _ := record["hop_count"].(int64)

		if attackerArn == "arn:aws:iam::111111111111:user/chain-attacker" &&
			targetArn == "arn:aws:iam::111111111111:role/chain-admin" &&
			hopCount == 2 {
			foundTwoHop = true
		}
		if attackerArn == "arn:aws:iam::111111111111:role/chain-intermediate" &&
			targetArn == "arn:aws:iam::111111111111:role/chain-admin" &&
			hopCount == 1 {
			foundOneHop = true
		}
	}
	assert.True(t, foundTwoHop, "should find 2-hop path from chain-attacker to chain-admin")
	assert.True(t, foundOneHop, "should find 1-hop path from chain-intermediate to chain-admin")
}

// ---------------------------------------------------------------------------
// Query Registry Completeness Test
// ---------------------------------------------------------------------------

func TestEnrichment_AllQueriesRegistered(t *testing.T) {
	// Verify that all expected enrichment and analysis query IDs are loaded
	allQueries := queries.ListQueries()

	expectedEnrichmentIDs := []string{
		"aws/enrich/accounts",
		"aws/enrich/extract_role_trust_relationships",
		"aws/enrich/extract_role_trusted_services",
		"aws/enrich/resource_to_role",
		"aws/enrich/set_admin_administrator_access",
		"aws/enrich/set_admin_inline_wildcard",
		"aws/enrich/set_privileged_access",
		"aws/enrich/set_ssm_enabled_roles",
		"aws/enrich/iam/link_policies_to_roles",
	}

	for i := 1; i <= 42; i++ {
		expectedEnrichmentIDs = append(expectedEnrichmentIDs, fmt.Sprintf("aws/enrich/privesc/method_%02d", i))
	}

	expectedAnalysisIDs := []string{
		"aws/analysis/external_role_trust",
		"aws/analysis/privesc_paths",
	}

	allExpected := append(expectedEnrichmentIDs, expectedAnalysisIDs...)

	querySet := make(map[string]bool, len(allQueries))
	for _, q := range allQueries {
		querySet[q] = true
	}

	for _, expectedID := range allExpected {
		assert.True(t, querySet[expectedID], "expected query %q to be registered", expectedID)
	}
}
