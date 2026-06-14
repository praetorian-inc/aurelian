package aws

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeFromGaadUser(t *testing.T) {
	user := types.UserDetail{
		Arn:        "arn:aws:iam::123456789012:user/test-user",
		UserName:   "test-user",
		UserId:     "AIDACKCEVSQ6C2EXAMPLE",
		Path:       "/",
		CreateDate: "2024-01-15T10:30:00Z",
		GroupList:  []string{"developers", "admins"},
		Tags: []types.Tag{
			{Key: "Environment", Value: "production"},
		},
	}

	node := NodeFromGaadUser(user)

	require.NotNil(t, node)
	assert.Equal(t, []string{"User", "Principal", "AWS::IAM::User"}, node.Labels)
	assert.Equal(t, []string{"Arn"}, node.UniqueKey)

	// Check properties - JSON tags use capital letters
	assert.Equal(t, "arn:aws:iam::123456789012:user/test-user", node.Properties["Arn"])
	assert.Equal(t, "User", node.Properties["_type"])
	assert.Equal(t, "AWS::IAM::User", node.Properties["_resourceType"])
	assert.Equal(t, "test-user", node.Properties["UserName"])
	assert.Equal(t, "AIDACKCEVSQ6C2EXAMPLE", node.Properties["UserId"])
}

func TestNodeFromGaadRole(t *testing.T) {
	role := types.RoleDetail{
		Arn:      "arn:aws:iam::123456789012:role/test-role",
		RoleName: "test-role",
		RoleId:   "AIDACKCEVSQ6C2EXAMPLE",
		Path:     "/",
		AssumeRolePolicyDocument: types.Policy{
			Version: "2012-10-17",
			Statement: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						Service: &types.DynaString{"lambda.amazonaws.com", "ec2.amazonaws.com"},
					},
					Action: &types.DynaString{"sts:AssumeRole"},
				},
			},
		},
	}

	node := NodeFromGaadRole(role)

	require.NotNil(t, node)
	assert.Equal(t, []string{"Role", "Principal", "AWS::IAM::Role"}, node.Labels)
	assert.Equal(t, []string{"Arn"}, node.UniqueKey)

	// Check properties
	assert.Equal(t, "arn:aws:iam::123456789012:role/test-role", node.Properties["Arn"])
	assert.Equal(t, "Role", node.Properties["_type"])
	assert.Equal(t, "AWS::IAM::Role", node.Properties["_resourceType"])
	assert.Equal(t, "test-role", node.Properties["RoleName"])

	// Check trusted_services extraction
	trustedServices, ok := node.Properties["trusted_services"].([]string)
	assert.True(t, ok, "trusted_services should be a []string")
	assert.ElementsMatch(t, []string{"lambda.amazonaws.com", "ec2.amazonaws.com"}, trustedServices)

	// A pure-service trust must not produce a trusted_federated property.
	_, hasFederated := node.Properties["trusted_federated"]
	assert.False(t, hasFederated, "trusted_federated should be absent for service-only trust")
}

// TestNodeFromGaadRoleFederatedTrust verifies that a Federated principal (e.g. a
// Cognito identity pool role trusting cognito-identity.amazonaws.com) is surfaced
// as trusted_federated, separate from trusted_services, so the cognito privesc
// guard can match it without polluting the trusted_services property.
func TestNodeFromGaadRoleFederatedTrust(t *testing.T) {
	role := types.RoleDetail{
		Arn:      "arn:aws:iam::123456789012:role/cognito-pool-authrole",
		RoleName: "cognito-pool-authrole",
		AssumeRolePolicyDocument: types.Policy{
			Version: "2012-10-17",
			Statement: &types.PolicyStatementList{
				{
					Effect: "Allow",
					Principal: &types.Principal{
						Federated: &types.DynaString{"cognito-identity.amazonaws.com"},
					},
					Action: &types.DynaString{"sts:AssumeRoleWithWebIdentity"},
				},
			},
		},
	}

	node := NodeFromGaadRole(role)

	require.NotNil(t, node)
	trustedFederated, ok := node.Properties["trusted_federated"].([]string)
	assert.True(t, ok, "trusted_federated should be a []string")
	assert.ElementsMatch(t, []string{"cognito-identity.amazonaws.com"}, trustedFederated)

	// Federated trust must not leak into the trusted_services property.
	_, hasServices := node.Properties["trusted_services"]
	assert.False(t, hasServices, "trusted_services should be absent for federated-only trust")
}

func TestNodeFromGaadGroup(t *testing.T) {
	group := types.GroupDetail{
		Arn:       "arn:aws:iam::123456789012:group/developers",
		GroupName: "developers",
		GroupId:   "AIDACKCEVSQ6C2EXAMPLE",
		Path:      "/",
	}

	node := NodeFromGaadGroup(group)

	require.NotNil(t, node)
	assert.Equal(t, []string{"Group", "Principal", "AWS::IAM::Group"}, node.Labels)
	assert.Equal(t, []string{"Arn"}, node.UniqueKey)

	// Check properties
	assert.Equal(t, "arn:aws:iam::123456789012:group/developers", node.Properties["Arn"])
	assert.Equal(t, "Group", node.Properties["_type"])
	assert.Equal(t, "AWS::IAM::Group", node.Properties["_resourceType"])
	assert.Equal(t, "developers", node.Properties["GroupName"])
}

func TestNodeFromAWSResource(t *testing.T) {
	tests := []struct {
		name          string
		resource      output.AWSResource
		wantLabels    []string
		wantShortName string
	}{
		{
			name: "S3 Bucket",
			resource: output.AWSResource{
				ResourceType: "AWS::S3::Bucket",
				ResourceID:   "test-bucket",
				ARN:          "arn:aws:s3:::test-bucket",
				AccountRef:   "123456789012",
				Region:       "us-east-1",
			},
			wantLabels:    []string{"Bucket", "Resource", "AWS::S3::Bucket"},
			wantShortName: "Bucket",
		},
		{
			name: "Lambda Function",
			resource: output.AWSResource{
				ResourceType: "AWS::Lambda::Function",
				ResourceID:   "my-function",
				ARN:          "arn:aws:lambda:us-east-1:123456789012:function:my-function",
				AccountRef:   "123456789012",
				Region:       "us-east-1",
			},
			wantLabels:    []string{"Function", "Resource", "AWS::Lambda::Function"},
			wantShortName: "Function",
		},
		{
			name: "empty ResourceType",
			resource: output.AWSResource{
				ResourceType: "",
				ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
			},
			wantLabels:    []string{"Resource"},
			wantShortName: "",
		},
		{
			name: "malformed ResourceType with only two parts",
			resource: output.AWSResource{
				ResourceType: "AWS::S3",
				ARN:          "arn:aws:s3:::test-bucket",
			},
			wantLabels:    []string{"Resource", "AWS::S3"},
			wantShortName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := NodeFromAWSResource(tt.resource)

			require.NotNil(t, node)
			assert.Equal(t, tt.wantLabels, node.Labels)
			assert.Equal(t, []string{"arn"}, node.UniqueKey)
			assert.Equal(t, tt.resource.ARN, node.Properties["arn"])
			assert.Equal(t, "Resource", node.Properties["_type"])
			assert.Equal(t, tt.resource.ResourceType, node.Properties["_resourceType"])

			// Verify no empty labels (would cause Neo4j syntax errors)
			for _, label := range node.Labels {
				assert.NotEmpty(t, label, "labels must not contain empty strings")
			}
		})
	}
}

// TestNodeFromAWSResourcePromotesRoleReference locks down the role-reference
// promotion: flattenStruct serializes cr.Properties into a single JSON
// string under "properties", so the role reference resource_to_role.yaml reads
// as a TOP-LEVEL Cypher property (resource.IamInstanceProfile / resource.Role)
// would otherwise always be null for collector- and ERD-derived resources.
// NodeFromAWSResource must promote it to a top-level node property. This test
// FAILS if the promotion is removed.
func TestNodeFromAWSResourcePromotesRoleReference(t *testing.T) {
	const (
		profileARN = "arn:aws:iam::123456789012:instance-profile/ip"
		roleARN    = "arn:aws:iam::123456789012:role/lambda-role"
	)

	tests := []struct {
		name     string
		resource output.AWSResource
		wantKey  string
		wantVal  string
	}{
		{
			name: "EC2 instance-profile ARN string form",
			resource: output.AWSResource{
				ResourceType: "AWS::EC2::Instance",
				ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-0string",
				Properties:   map[string]any{"IamInstanceProfile": profileARN},
			},
			wantKey: "IamInstanceProfile",
			wantVal: profileARN,
		},
		{
			name: "EC2 instance-profile {Arn:...} map form",
			resource: output.AWSResource{
				ResourceType: "AWS::EC2::Instance",
				ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-0map",
				Properties:   map[string]any{"IamInstanceProfile": map[string]any{"Arn": profileARN}},
			},
			wantKey: "IamInstanceProfile",
			wantVal: profileARN,
		},
		{
			name: "Lambda function role",
			resource: output.AWSResource{
				ResourceType: "AWS::Lambda::Function",
				ARN:          "arn:aws:lambda:us-east-1:123456789012:function:fn",
				Properties:   map[string]any{"Role": roleARN},
			},
			wantKey: "Role",
			wantVal: roleARN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := NodeFromAWSResource(tt.resource)
			require.NotNil(t, node)
			assert.Equal(t, tt.wantVal, node.Properties[tt.wantKey],
				"role reference must be promoted to a top-level node property so resource_to_role.yaml can read it")
		})
	}

	t.Run("no role reference does not instantiate empty key", func(t *testing.T) {
		node := NodeFromAWSResource(output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ARN:          "arn:aws:ec2:us-east-1:123456789012:instance/i-0none",
			Properties:   map[string]any{"State": "running"},
		})
		require.NotNil(t, node)
		_, present := node.Properties["IamInstanceProfile"]
		assert.False(t, present, "must not set an empty IamInstanceProfile when none is present")
	})
}

// TestProductionLoadPathBuildsComputeNodeWithRole locks down the LIVE neo4j load path:
// plugin.GraphFormatter.Format builds nodes ONLY from output.AWSIAMResource via
// NodeFromAWSIAMResource. The graph recon module emits collected compute resources as plain
// output.AWSResource wrapped with output.FromAWSResource so they match that case. This test
// drives that exact production transform — FromAWSResource -> NodeFromAWSIAMResource — and
// asserts each compute type (a) becomes a node with the right _resourceType and (b) carries
// the role reference where the HAS_ROLE enricher reads it:
//   - service types (AppRunner / Batch / Bedrock): the role ARN appears as a QUOTED value
//     inside the flattened `properties` JSON string (resource_service_role.yaml's match).
//   - Lambda: the role ARN is promoted to a top-level `Role` node prop (resource_to_role.yaml).
//
// It guards against a plain AWSResource being dropped before CreateNodes; the integration and
// seeded-neo4j tests bypass GraphFormatter.Format and so do not exercise this path.
func TestProductionLoadPathBuildsComputeNodeWithRole(t *testing.T) {
	const (
		apprunnerRole = "arn:aws:iam::000000000000:role/pl-apprunner-002-instance-role"
		batchRole     = "arn:aws:iam::000000000000:role/pl-batch-002-job-role"
		bedrockRole   = "arn:aws:iam::000000000000:role/pl-bedrock-002-exec-role"
		lambdaRole    = "arn:aws:iam::000000000000:role/pl-lambda-003-exec-role"
		cognitoRole   = "arn:aws:iam::000000000000:role/pl-cognito-001-unauth-role"
	)

	// servicePropertyRole asserts the role ARN appears as a quoted value inside the
	// flattened `properties` JSON string — exactly what resource_service_role.yaml's
	// `resource.properties CONTAINS ('"' + role.Arn + '"')` clause matches.
	servicePropertyRole := func(t *testing.T, node *graph.Node, roleARN string) {
		t.Helper()
		props, ok := node.Properties["properties"].(string)
		require.True(t, ok, "flattened properties must be a JSON string for resource_service_role.yaml to match")
		assert.Contains(t, props, `"`+roleARN+`"`,
			"role ARN must appear as a quoted value in the properties JSON for the HAS_ROLE match")
	}

	tests := []struct {
		name     string
		resource output.AWSResource
		assert   func(t *testing.T, node *graph.Node)
	}{
		{
			name: "AppRunner service",
			resource: output.AWSResource{
				ResourceType: "AWS::AppRunner::Service",
				ARN:          "arn:aws:apprunner:us-east-1:000000000000:service/pl-apprunner-002/abc",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties:   map[string]any{"InstanceRoleArn": apprunnerRole},
			},
			assert: func(t *testing.T, node *graph.Node) { servicePropertyRole(t, node, apprunnerRole) },
		},
		{
			name: "Batch job definition",
			resource: output.AWSResource{
				ResourceType: "AWS::Batch::JobDefinition",
				ARN:          "arn:aws:batch:us-east-1:000000000000:job-definition/pl-batch-002:1",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties:   map[string]any{"JobRoleArn": batchRole},
			},
			assert: func(t *testing.T, node *graph.Node) { servicePropertyRole(t, node, batchRole) },
		},
		{
			name: "Bedrock AgentCore code interpreter",
			resource: output.AWSResource{
				ResourceType: "AWS::BedrockAgentCore::CodeInterpreter",
				ARN:          "arn:aws:bedrock-agentcore:us-east-1:000000000000:code-interpreter/pl-bedrock-002",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties:   map[string]any{"ExecutionRoleArn": bedrockRole},
			},
			assert: func(t *testing.T, node *graph.Node) { servicePropertyRole(t, node, bedrockRole) },
		},
		{
			name: "Lambda function without resource policy",
			resource: output.AWSResource{
				ResourceType: "AWS::Lambda::Function",
				ARN:          "arn:aws:lambda:us-east-1:000000000000:function:pl-lambda-003-target",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties:   map[string]any{"Role": lambdaRole},
			},
			assert: func(t *testing.T, node *graph.Node) {
				// resource_to_role.yaml reads the TOP-LEVEL promoted Role prop, not properties.
				assert.Equal(t, lambdaRole, node.Properties["Role"],
					"Lambda Role must be promoted to a top-level node prop for resource_to_role.yaml")
			},
		},
		{
			// A launch template references its role via an instance profile (ARN or name),
			// promoted to a top-level IamInstanceProfile prop so set_launch_template_role.yaml
			// can match it against the role's InstanceProfileList (same path as an EC2 instance).
			name: "EC2 launch template",
			resource: output.AWSResource{
				ResourceType: "AWS::EC2::LaunchTemplate",
				ARN:          "arn:aws:ec2:us-east-1:000000000000:launch-template/lt-ec2-005",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties:   map[string]any{"IamInstanceProfile": "arn:aws:iam::000000000000:instance-profile/lt-ip"},
			},
			assert: func(t *testing.T, node *graph.Node) {
				assert.Equal(t, "arn:aws:iam::000000000000:instance-profile/lt-ip", node.Properties["IamInstanceProfile"],
					"launch-template IamInstanceProfile must be promoted to a top-level node prop for set_launch_template_role.yaml")
			},
		},
		{
			// An identity pool binds its role ARN directly (resource_service_role.yaml's
			// quoted-properties match) and promotes AllowUnauthenticatedIdentities so the
			// cognito enricher can relax its GetId/GetCredentials guard for unauth pools.
			name: "Cognito identity pool",
			resource: output.AWSResource{
				ResourceType: "AWS::Cognito::IdentityPool",
				ARN:          "arn:aws:cognito-identity:us-east-1:000000000000:identitypool/us-east-1:pool-1",
				AccountRef:   "000000000000",
				Region:       "us-east-1",
				Properties: map[string]any{
					"AllowUnauthenticatedIdentities": true,
					"unauthenticatedRole":            cognitoRole,
				},
			},
			assert: func(t *testing.T, node *graph.Node) {
				servicePropertyRole(t, node, cognitoRole)
				assert.Equal(t, true, node.Properties["AllowUnauthenticatedIdentities"],
					"AllowUnauthenticatedIdentities must be promoted to a top-level node prop for the cognito enricher relax")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Drive the production load path exactly: GraphFormatter.Format wraps the
			// emitted result and calls NodeFromAWSIAMResource on it.
			entity := output.FromAWSResource(tt.resource)
			node := NodeFromAWSIAMResource(entity)

			require.NotNil(t, node, "production load path must produce a node, not drop the resource")
			assert.Equal(t, tt.resource.ResourceType, node.Properties["_resourceType"])
			assert.Equal(t, "Resource", node.Properties["_type"])
			assert.Contains(t, node.Labels, tt.resource.ResourceType)
			assert.Equal(t, tt.resource.ARN, node.Properties["arn"])
			tt.assert(t, node)
		})
	}
}

// TestGraphFormatterTypeSwitchContract documents the exact reason the recon module wraps
// emitted resources: plugin.GraphFormatter.Format selects nodes with a Go type switch on
// `case output.AWSIAMResource`. A plain output.AWSResource does NOT satisfy that case even
// though AWSIAMResource embeds it (Go type switches match the dynamic type exactly, not an
// embedded field), so an unwrapped resource is dropped; the FromAWSResource-wrapped form is
// matched and loaded. This test fails if that embedding assumption ever changes.
func TestGraphFormatterTypeSwitchContract(t *testing.T) {
	plain := output.AWSResource{ResourceType: "AWS::Batch::JobDefinition", ARN: "arn:aws:batch:us-east-1:000000000000:job-definition/x:1"}

	// Mirror GraphFormatter.Format's selection contract over model.AurelianModel values.
	matched := func(v any) bool {
		switch v.(type) {
		case output.AWSIAMResource:
			return true
		default:
			return false
		}
	}

	assert.False(t, matched(plain), "plain AWSResource must NOT match the load path's AWSIAMResource case, so an unwrapped resource is dropped")
	assert.True(t, matched(output.FromAWSResource(plain)), "FromAWSResource-wrapped resource must match so it loads as a node")
}

func TestNodeFromServicePrincipal(t *testing.T) {
	node := NodeFromServicePrincipal("lambda.amazonaws.com")

	require.NotNil(t, node)
	assert.Equal(t, []string{"ServicePrincipal", "Principal"}, node.Labels)
	assert.Equal(t, []string{"service"}, node.UniqueKey)
	assert.Equal(t, "lambda.amazonaws.com", node.Properties["service"])
	assert.Equal(t, "ServicePrincipal", node.Properties["_type"])
}

func TestRelationshipFromFullResult(t *testing.T) {
	tests := []struct {
		name         string
		result       iam.FullResult
		wantRelType  string
		wantStartArn string
	}{
		{
			name: "User principal",
			result: iam.FullResult{
				Principal: &types.UserDetail{
					Arn:      "arn:aws:iam::123456789012:user/test-user",
					UserName: "test-user",
				},
				Resource: &types.EnrichedResourceDescription{
					TypeName:   "AWS::S3::Bucket",
					Identifier: "test-bucket",
					AccountId:  "123456789012",
					Region:     "us-east-1",
				},
				Action: "s3:GetObject",
			},
			wantRelType:  "S3_GETOBJECT",
			wantStartArn: "arn:aws:iam::123456789012:user/test-user",
		},
		{
			name: "Role principal",
			result: iam.FullResult{
				Principal: &types.RoleDetail{
					Arn:      "arn:aws:iam::123456789012:role/test-role",
					RoleName: "test-role",
				},
				Resource: &types.EnrichedResourceDescription{
					TypeName:   "AWS::Lambda::Function",
					Identifier: "my-function",
					AccountId:  "123456789012",
					Region:     "us-east-1",
				},
				Action: "lambda:InvokeFunction",
			},
			wantRelType:  "LAMBDA_INVOKEFUNCTION",
			wantStartArn: "arn:aws:iam::123456789012:role/test-role",
		},
		{
			name: "Group principal",
			result: iam.FullResult{
				Principal: &types.GroupDetail{
					Arn:       "arn:aws:iam::123456789012:group/developers",
					GroupName: "developers",
				},
				Resource: &types.EnrichedResourceDescription{
					TypeName:   "AWS::DynamoDB::Table",
					Identifier: "users-table",
					AccountId:  "123456789012",
					Region:     "us-east-1",
				},
				Action: "dynamodb:PutItem",
			},
			wantRelType:  "DYNAMODB_PUTITEM",
			wantStartArn: "arn:aws:iam::123456789012:group/developers",
		},
		{
			name: "String service principal",
			result: iam.FullResult{
				Principal: "lambda.amazonaws.com",
				Resource: &types.EnrichedResourceDescription{
					TypeName:   "AWS::IAM::Role",
					Identifier: "execution-role",
					AccountId:  "123456789012",
					Region:     "us-east-1",
				},
				Action: "sts:AssumeRole",
			},
			wantRelType:  "STS_ASSUMEROLE",
			wantStartArn: "", // Service principals don't have ARN
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := RelationshipFromFullResult(tt.result)

			require.NotNil(t, rel)
			assert.Equal(t, tt.wantRelType, rel.Type)
			require.NotNil(t, rel.StartNode)
			require.NotNil(t, rel.EndNode)

			if tt.wantStartArn != "" {
				assert.Equal(t, tt.wantStartArn, rel.StartNode.Properties["Arn"])
			}
		})
	}
}

func TestNormalizeActionToRelType(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"s3:GetObject", "S3_GETOBJECT"},
		{"sts:AssumeRole", "STS_ASSUMEROLE"},
		{"lambda:InvokeFunction", "LAMBDA_INVOKEFUNCTION"},
		{"dynamodb:PutItem", "DYNAMODB_PUTITEM"},
		{"ec2:DescribeInstances", "EC2_DESCRIBEINSTANCES"},
		{"iam:CreateRole", "IAM_CREATEROLE"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := normalizeActionToRelType(tt.action)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseResourceType(t *testing.T) {
	tests := []struct {
		resourceType string
		want         []string
	}{
		{"AWS::S3::Bucket", []string{"AWS", "S3", "Bucket"}},
		{"AWS::Lambda::Function", []string{"AWS", "Lambda", "Function"}},
		{"AWS::IAM::Role", []string{"AWS", "IAM", "Role"}},
		{"AWS::DynamoDB::Table", []string{"AWS", "DynamoDB", "Table"}},
	}

	for _, tt := range tests {
		t.Run(tt.resourceType, func(t *testing.T) {
			got := parseResourceType(tt.resourceType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFlattenStructFiltersNonPrimitives(t *testing.T) {
	type ManagedPolicy struct {
		PolicyArn  string `json:"PolicyArn"`
		PolicyName string `json:"PolicyName"`
	}

	type TestUser struct {
		UserName                string          `json:"UserName"`
		UserId                  string          `json:"UserId"`
		Age                     float64         `json:"Age"`
		Active                  bool            `json:"Active"`
		Tags                    []string        `json:"Tags"`
		Numbers                 []float64       `json:"Numbers"`
		AttachedManagedPolicies []ManagedPolicy `json:"AttachedManagedPolicies"` // Array of objects - should be JSON string
		PermissionsBoundary     ManagedPolicy   `json:"PermissionsBoundary"`     // Nested object - should be JSON string
		EmptyArray              []string        `json:"EmptyArray"`              // Empty array - should be filtered
		EmptyObjectArray        []ManagedPolicy `json:"EmptyObjectArray"`        // Empty object array - should be filtered
	}

	user := TestUser{
		UserName: "test-user",
		UserId:   "AIDAEXAMPLE",
		Age:      42.5,
		Active:   true,
		Tags:     []string{"prod", "admin"},
		Numbers:  []float64{1.5, 2.7, 3.9},
		AttachedManagedPolicies: []ManagedPolicy{
			{PolicyArn: "arn:aws:iam::aws:policy/ReadOnly", PolicyName: "ReadOnly"},
			{PolicyArn: "arn:aws:iam::aws:policy/WriteOnly", PolicyName: "WriteOnly"},
		},
		PermissionsBoundary: ManagedPolicy{
			PolicyArn:  "arn:aws:iam::aws:policy/Boundary",
			PolicyName: "BoundaryPolicy",
		},
		EmptyArray:       []string{},
		EmptyObjectArray: []ManagedPolicy{},
	}

	result := flattenStruct(user)

	// Primitives should be present
	assert.Equal(t, "test-user", result["UserName"], "String primitive should be present")
	assert.Equal(t, "AIDAEXAMPLE", result["UserId"], "String primitive should be present")
	assert.Equal(t, 42.5, result["Age"], "Number primitive should be present")
	assert.Equal(t, true, result["Active"], "Boolean primitive should be present")

	// Arrays of primitives should be present
	tags, ok := result["Tags"]
	assert.True(t, ok, "Tags array should be present")
	assert.IsType(t, []string{}, tags, "Tags should be []string")
	assert.Equal(t, []string{"prod", "admin"}, tags)

	numbers, ok := result["Numbers"]
	assert.True(t, ok, "Numbers array should be present")
	assert.Equal(t, []interface{}{1.5, 2.7, 3.9}, numbers, "Numbers should be array of numbers")

	// Nested object should be JSON string
	boundary, ok := result["PermissionsBoundary"]
	assert.True(t, ok, "PermissionsBoundary should be present as JSON string")
	assert.IsType(t, "", boundary, "PermissionsBoundary should be a string")
	assert.Contains(t, boundary.(string), "PolicyArn", "JSON string should contain PolicyArn")
	assert.Contains(t, boundary.(string), "Boundary", "JSON string should contain value")

	// Array of objects should be JSON string
	policies, ok := result["AttachedManagedPolicies"]
	assert.True(t, ok, "AttachedManagedPolicies should be present as JSON string")
	assert.IsType(t, "", policies, "AttachedManagedPolicies should be a string")
	assert.Contains(t, policies.(string), "ReadOnly", "JSON string should contain policy names")

	// Empty arrays should be filtered out (return nil)
	_, ok = result["EmptyArray"]
	assert.False(t, ok, "Empty string array should be filtered out")

	_, ok = result["EmptyObjectArray"]
	assert.False(t, ok, "Empty object array should be filtered out")
}

func TestToNeo4jPropertyPrimitives(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{"string", "test", "test"},
		{"float64", 42.5, 42.5},
		{"bool", true, true},
		{"nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toNeo4jProperty(tt.value)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToNeo4jPropertyArrays(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  interface{}
	}{
		{
			"string array",
			[]interface{}{"a", "b", "c"},
			[]string{"a", "b", "c"},
		},
		{
			"number array",
			[]interface{}{1.0, 2.0, 3.0},
			[]interface{}{1.0, 2.0, 3.0},
		},
		{
			"empty array",
			[]interface{}{},
			nil, // Empty arrays should be filtered
		},
		{
			"mixed array", // Mixed arrays become JSON string - not tested here, see TestToNeo4jArrayHandlesObjects
			[]interface{}{"string", 42.0},
			"[\"string\",42]", // Will be serialized as JSON string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toNeo4jProperty(tt.value)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestToNeo4jArrayHandlesObjects(t *testing.T) {
	// Array of objects should become JSON string
	arr := []interface{}{
		map[string]interface{}{"key": "value1"},
		map[string]interface{}{"key": "value2"},
	}

	result := toNeo4jArray(arr)

	require.NotNil(t, result)
	assert.IsType(t, "", result, "Array of objects should be serialized as JSON string")

	jsonStr, ok := result.(string)
	require.True(t, ok)
	assert.Contains(t, jsonStr, "key")
	assert.Contains(t, jsonStr, "value1")
}
