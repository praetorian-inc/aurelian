package secrets

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLambdaGetFunctionClient struct {
	codeURL string
	runtime string
	err     error
}

func (m *mockLambdaGetFunctionClient) GetFunction(
	ctx context.Context,
	input *lambda.GetFunctionInput,
	opts ...func(*lambda.Options),
) (*lambda.GetFunctionOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := &lambda.GetFunctionOutput{
		Code: &lambdatypes.FunctionCodeLocation{
			Location: aws.String(m.codeURL),
		},
		Configuration: &lambdatypes.FunctionConfiguration{
			Runtime: lambdatypes.Runtime(m.runtime),
		},
	}
	return out, nil
}

func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestExtractLambda_WithCode(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"handler.py":  "import boto3\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
		"config.json": `{"db_password": "secret123"}`,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipData)
	}))
	defer server.Close()

	client := &mockLambdaGetFunctionClient{
		codeURL: server.URL,
		runtime: "python3.12",
	}

	r := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:my-func",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"FunctionName": "my-func"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractLambdaWithClient(client, http.DefaultClient, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 2)

	labels := map[string]bool{}
	for _, item := range items {
		labels[item.Label] = true
		assert.Equal(t, r.ResourceID, item.ResourceID)
		assert.Equal(t, "us-east-1", item.Region)
	}
	assert.True(t, labels["handler.py"])
	assert.True(t, labels["config.json"])
}

func TestExtractLambda_NoCodeURL(t *testing.T) {
	client := &mockLambdaGetFunctionClient{
		codeURL: "",
		runtime: "python3.12",
	}

	r := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:my-func",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"FunctionName": "my-func"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractLambdaWithClient(client, http.DefaultClient, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
