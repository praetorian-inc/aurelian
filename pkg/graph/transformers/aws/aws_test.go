package aws

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
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
				Platform:     "aws",
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
				Platform:     "aws",
				ResourceType: "AWS::Lambda::Function",
				ResourceID:   "my-function",
				ARN:          "arn:aws:lambda:us-east-1:123456789012:function:my-function",
				AccountRef:   "123456789012",
				Region:       "us-east-1",
			},
			wantLabels:    []string{"Function", "Resource", "AWS::Lambda::Function"},
			wantShortName: "Function",
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
		})
	}
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
