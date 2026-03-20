package resourcepolicies

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertACLGrantsToStatements_AllUsers(t *testing.T) {
	grants := []s3types.Grant{
		{
			Grantee: &s3types.Grantee{
				URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
				Type: s3types.TypeGroup,
			},
			Permission: s3types.PermissionRead,
		},
	}

	stmts := ConvertACLGrantsToStatements(grants, "my-bucket")
	require.Len(t, stmts, 1)
	assert.Equal(t, "Allow", stmts[0].Effect)
	assert.Contains(t, ([]string)(*stmts[0].Action), "s3:GetObject")
	assert.Contains(t, ([]string)(*stmts[0].Action), "s3:ListBucket")
}

func TestConvertACLGrantsToStatements_AuthenticatedUsers(t *testing.T) {
	grants := []s3types.Grant{
		{
			Grantee: &s3types.Grantee{
				URI:  aws.String("http://acs.amazonaws.com/groups/global/AuthenticatedUsers"),
				Type: s3types.TypeGroup,
			},
			Permission: s3types.PermissionWrite,
		},
	}

	stmts := ConvertACLGrantsToStatements(grants, "my-bucket")
	require.Len(t, stmts, 1)
	assert.Contains(t, ([]string)(*stmts[0].Action), "s3:PutObject")
}

func TestConvertACLGrantsToStatements_PrivateGrant(t *testing.T) {
	grants := []s3types.Grant{
		{
			Grantee: &s3types.Grantee{
				ID:   aws.String("canonical-user-id"),
				Type: s3types.TypeCanonicalUser,
			},
			Permission: s3types.PermissionRead,
		},
	}

	stmts := ConvertACLGrantsToStatements(grants, "my-bucket")
	assert.Empty(t, stmts)
}

func TestConvertACLGrantsToStatements_FullControl(t *testing.T) {
	grants := []s3types.Grant{
		{
			Grantee: &s3types.Grantee{
				URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
				Type: s3types.TypeGroup,
			},
			Permission: s3types.PermissionFullControl,
		},
	}

	stmts := ConvertACLGrantsToStatements(grants, "my-bucket")
	require.Len(t, stmts, 1)
	assert.Contains(t, ([]string)(*stmts[0].Action), "s3:*")
}

func TestConvertACLGrantsToStatements_Empty(t *testing.T) {
	stmts := ConvertACLGrantsToStatements(nil, "my-bucket")
	assert.Empty(t, stmts)
}

func TestACLPermissionToActions(t *testing.T) {
	tests := []struct {
		perm     s3types.Permission
		expected []string
	}{
		{s3types.PermissionRead, []string{"s3:GetObject", "s3:ListBucket"}},
		{s3types.PermissionWrite, []string{"s3:PutObject", "s3:DeleteObject"}},
		{s3types.PermissionReadAcp, []string{"s3:GetBucketAcl", "s3:GetObjectAcl"}},
		{s3types.PermissionWriteAcp, []string{"s3:PutBucketAcl", "s3:PutObjectAcl"}},
		{s3types.PermissionFullControl, []string{"s3:*"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.perm), func(t *testing.T) {
			actions := aclPermissionToActions(tt.perm)
			assert.Equal(t, tt.expected, actions)
		})
	}
}

func TestCreateBlockPublicAccessDenyPolicy(t *testing.T) {
	policy := createBlockPublicAccessDenyPolicy("my-bucket")
	require.NotNil(t, policy)
	require.NotNil(t, policy.Statement)
	require.Len(t, *policy.Statement, 1)

	stmt := (*policy.Statement)[0]
	assert.Equal(t, "Deny", stmt.Effect)
	assert.Equal(t, "BlockPublicAccess", stmt.Sid)
}

func TestMergeS3Policies_BothNil(t *testing.T) {
	result := mergeS3Policies(nil, nil, "my-bucket")
	assert.Nil(t, result)
}

func TestMergeS3Policies_OnlyACL(t *testing.T) {
	grants := []s3types.Grant{
		{
			Grantee: &s3types.Grantee{
				URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
				Type: s3types.TypeGroup,
			},
			Permission: s3types.PermissionRead,
		},
	}
	aclStmts := ConvertACLGrantsToStatements(grants, "my-bucket")

	result := mergeS3Policies(nil, aclStmts, "my-bucket")
	require.NotNil(t, result)
	assert.Len(t, *result.Statement, 1)
}

// mockS3ExtendedClient for testing FetchS3BucketPolicyExtended
type mockS3ExtendedClient struct {
	// S3Client methods
	policyOutput *s3.GetBucketPolicyOutput
	policyError  error
	// Extended methods
	aclOutput      *s3.GetBucketAclOutput
	aclError       error
	blockOutput    *s3.GetPublicAccessBlockOutput
	blockError     error
	locationOutput *s3.GetBucketLocationOutput
	locationError  error
}

func (m *mockS3ExtendedClient) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return m.policyOutput, m.policyError
}

func (m *mockS3ExtendedClient) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return m.aclOutput, m.aclError
}

func (m *mockS3ExtendedClient) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return m.blockOutput, m.blockError
}

func (m *mockS3ExtendedClient) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	return m.locationOutput, m.locationError
}

func TestFetchS3BucketPolicyExtended_BlockPublicAccess(t *testing.T) {
	client := &mockS3ExtendedClient{
		locationOutput: &s3.GetBucketLocationOutput{},
		blockOutput: &s3.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				IgnorePublicAcls:      aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
				BlockPublicAcls:       aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(true),
			},
		},
	}

	resource := &output.AWSResource{
		ResourceID: "my-bucket",
	}

	policy, err := FetchS3BucketPolicyExtended(context.Background(), client, resource, nil)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "Deny", (*policy.Statement)[0].Effect)
}

func TestFetchS3BucketPolicyExtended_PublicACL(t *testing.T) {
	client := &mockS3ExtendedClient{
		locationOutput: &s3.GetBucketLocationOutput{},
		blockError: &smithy.GenericAPIError{
			Code:    "NoSuchPublicAccessBlockConfiguration",
			Message: "The public access block configuration was not found",
		},
		policyError: &smithy.GenericAPIError{
			Code:    "NoSuchBucketPolicy",
			Message: "The bucket policy does not exist",
		},
		aclOutput: &s3.GetBucketAclOutput{
			Grants: []s3types.Grant{
				{
					Grantee: &s3types.Grantee{
						URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
						Type: s3types.TypeGroup,
					},
					Permission: s3types.PermissionRead,
				},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceID: "my-bucket",
	}

	policy, err := FetchS3BucketPolicyExtended(context.Background(), client, resource, nil)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Len(t, *policy.Statement, 1)
	assert.Equal(t, "Allow", (*policy.Statement)[0].Effect)
}

func TestFetchS3BucketPolicyExtended_NoBucketName(t *testing.T) {
	resource := &output.AWSResource{}

	policy, err := FetchS3BucketPolicyExtended(context.Background(), &mockS3ExtendedClient{}, resource, nil)
	require.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchS3BucketPolicyExtended_RegionFiltering_SkipOutsideRegion(t *testing.T) {
	client := &mockS3ExtendedClient{
		locationOutput: &s3.GetBucketLocationOutput{
			LocationConstraint: s3types.BucketLocationConstraintEuWest1,
		},
	}

	resource := &output.AWSResource{
		ResourceID: "my-bucket",
	}

	// Only allow us-east-1, bucket is in eu-west-1 => should return nil
	policy, err := FetchS3BucketPolicyExtended(context.Background(), client, resource, []string{"us-east-1"})
	require.NoError(t, err)
	assert.Nil(t, policy)
}

func TestFetchS3BucketPolicyExtended_RegionFiltering_DefaultUsEast1(t *testing.T) {
	client := &mockS3ExtendedClient{
		locationOutput: &s3.GetBucketLocationOutput{
			// Empty LocationConstraint means us-east-1
			LocationConstraint: "",
		},
		blockError: &smithy.GenericAPIError{
			Code:    "NoSuchPublicAccessBlockConfiguration",
			Message: "not found",
		},
		policyError: &smithy.GenericAPIError{
			Code:    "NoSuchBucketPolicy",
			Message: "not found",
		},
		aclOutput: &s3.GetBucketAclOutput{
			Grants: []s3types.Grant{},
		},
	}

	resource := &output.AWSResource{
		ResourceID: "my-bucket",
	}

	// Allow us-east-1, bucket has empty location (defaults to us-east-1) => should proceed
	policy, err := FetchS3BucketPolicyExtended(context.Background(), client, resource, []string{"us-east-1"})
	require.NoError(t, err)
	// No policy or ACL grants, so result is nil
	assert.Nil(t, policy)
}

func TestMergeS3Policies_BothPolicyAndACL(t *testing.T) {
	bucketPolicy := &types.Policy{
		Version: "2012-10-17",
		Statement: &types.PolicyStatementList{
			{
				Sid:    "ExistingPolicy",
				Effect: "Allow",
				Principal: &types.Principal{
					AWS: types.NewDynaString([]string{"arn:aws:iam::123456789012:root"}),
				},
				Action:   types.NewDynaString([]string{"s3:GetObject"}),
				Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket/*"}),
			},
		},
	}

	aclStmts := []types.PolicyStatement{
		{
			Sid:    "ACL-READ",
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: types.NewDynaString([]string{"*"}),
			},
			Action:   types.NewDynaString([]string{"s3:GetObject", "s3:ListBucket"}),
			Resource: types.NewDynaString([]string{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"}),
		},
	}

	result := mergeS3Policies(bucketPolicy, aclStmts, "my-bucket")
	require.NotNil(t, result)
	require.NotNil(t, result.Statement)
	assert.Len(t, *result.Statement, 2, "should contain both bucket policy and ACL statements")
	assert.Equal(t, "ExistingPolicy", (*result.Statement)[0].Sid)
	assert.Equal(t, "ACL-READ", (*result.Statement)[1].Sid)
}

func TestFetchS3BucketPolicyExtended_BlockPublicAccessPartial(t *testing.T) {
	client := &mockS3ExtendedClient{
		locationOutput: &s3.GetBucketLocationOutput{},
		blockOutput: &s3.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(true),
				IgnorePublicAcls:      aws.Bool(false),
				BlockPublicPolicy:     aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(false),
			},
		},
		policyError: &smithy.GenericAPIError{
			Code:    "NoSuchBucketPolicy",
			Message: "not found",
		},
		aclOutput: &s3.GetBucketAclOutput{
			Grants: []s3types.Grant{
				{
					Grantee: &s3types.Grantee{
						URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
						Type: s3types.TypeGroup,
					},
					Permission: s3types.PermissionRead,
				},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceID: "my-bucket",
	}

	policy, err := FetchS3BucketPolicyExtended(context.Background(), client, resource, nil)
	require.NoError(t, err)
	require.NotNil(t, policy, "should fall through to check ACL when block is partial")
	assert.Equal(t, "Allow", (*policy.Statement)[0].Effect, "should return ACL-derived Allow, not block Deny")
}
