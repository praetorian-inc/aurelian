package publicaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEvaluationContexts_S3(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::S3::Bucket", "arn:aws:s3:::my-bucket", "123456789012")
	require.NoError(t, err)
	assert.NotEmpty(t, contexts)

	// S3 has 5 actions x 2 context types = 10 contexts
	assert.Len(t, contexts, 10)

	// Verify first context is anonymous
	assert.Equal(t, "s3:GetObject", contexts[0].Action)
	assert.Equal(t, "arn:aws:iam::anonymous", contexts[0].Context.PrincipalArn)

	// Verify second context is cross-account
	assert.Equal(t, "s3:GetObject", contexts[1].Action)
	assert.Equal(t, "arn:aws:iam::999999999999:root", contexts[1].Context.PrincipalArn)
}

func TestGetEvaluationContexts_SNS(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::SNS::Topic", "arn:aws:sns:us-east-1:123456789012:my-topic", "123456789012")
	require.NoError(t, err)
	// 3 actions x 2 context types = 6
	assert.Len(t, contexts, 6)
}

func TestGetEvaluationContexts_SQS(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::SQS::Queue", "arn:aws:sqs:us-east-1:123456789012:my-queue", "123456789012")
	require.NoError(t, err)
	// 3 actions x 2 context types = 6
	assert.Len(t, contexts, 6)
}

func TestGetEvaluationContexts_Lambda(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::Lambda::Function", "arn:aws:lambda:us-east-1:123456789012:function:my-func", "123456789012")
	require.NoError(t, err)
	// 2 actions x 2 context types = 4
	assert.Len(t, contexts, 4)
}

func TestGetEvaluationContexts_EFS(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::EFS::FileSystem", "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-123", "123456789012")
	require.NoError(t, err)
	// 3 actions x 2 context types = 6
	assert.Len(t, contexts, 6)
}

func TestGetEvaluationContexts_OpenSearch(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::OpenSearchService::Domain", "arn:aws:es:us-east-1:123456789012:domain/my-domain", "123456789012")
	require.NoError(t, err)
	// 3 actions x 2 context types = 6
	assert.Len(t, contexts, 6)
}

func TestGetEvaluationContexts_Elasticsearch(t *testing.T) {
	contexts, err := GetEvaluationContexts("AWS::Elasticsearch::Domain", "arn:aws:es:us-east-1:123456789012:domain/my-domain", "123456789012")
	require.NoError(t, err)
	// Same as OpenSearch: 3 actions x 2 context types = 6
	assert.Len(t, contexts, 6)
}

func TestGetEvaluationContexts_Unsupported(t *testing.T) {
	_, err := GetEvaluationContexts("AWS::Foo::Bar", "arn:aws:foo:us-east-1:123456789012:bar", "123456789012")
	assert.Error(t, err)
}

func TestAnonymousContext(t *testing.T) {
	ctx := anonymousContext("123456789012")
	assert.Equal(t, "arn:aws:iam::anonymous", ctx.PrincipalArn)
	assert.Equal(t, "123456789012", ctx.ResourceAccount)
	assert.NotNil(t, ctx.SecureTransport)
	assert.True(t, *ctx.SecureTransport)
}

func TestCrossAccountContext(t *testing.T) {
	ctx := crossAccountContext("123456789012")
	assert.Equal(t, "arn:aws:iam::999999999999:root", ctx.PrincipalArn)
	assert.Equal(t, "999999999999", ctx.PrincipalAccount)
	assert.Equal(t, "123456789012", ctx.ResourceAccount)
}
