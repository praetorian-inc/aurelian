package extraction_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestAdmission_LambdaARNEnumerationAndExtraction(t *testing.T) {
	var admissions, attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		assert.Equal(t, attempt, admissions.Load())
		assert.Contains(t, r.URL.Path, "/functions/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Configuration":{"FunctionName":"test","FunctionArn":"arn:aws:lambda:us-east-1:123456789012:function:test"}}`))
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL", server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/credentials")

	opts := plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			BeforeRequest: func(context.Context) error { admissions.Add(1); return nil },
		},
		Regions:     []string{"us-east-1"},
		Concurrency: 1,
	}
	enumerator := enumeration.NewLambdaFunctionEnumerator(opts, enumeration.NewAWSConfigProvider(opts), enumeration.NewSkipReport())
	extractor := extraction.NewAWSExtractor(opts, extraction.Config{FailOnError: true})
	resources := pipeline.New[output.AWSResource]()
	pipeline.Pipe(pipeline.From("arn:aws:lambda:us-east-1:123456789012:function:test"), enumerator.EnumerateByARN, resources)
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(resources, extractor.Extract, extracted)
	for range extracted.Range() {
	}
	require.NoError(t, extracted.Wait())
	assert.EqualValues(t, 2, attempts.Load())
	assert.Equal(t, attempts.Load(), admissions.Load())
}
