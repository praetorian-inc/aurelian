package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindSecrets_CheckpointRejectsPartialScan(t *testing.T) {
	for _, test := range []struct {
		checkpoint      string
		failedOperation string
	}{
		{"logs-since", "GetResource"},
		{"logs-since", "FilterLogEvents"},
		{"modified-since", "GetResource"},
		{"modified-since", "FilterLogEvents"},
	} {
		t.Run(test.checkpoint+"/"+test.failedOperation, func(t *testing.T) {
			failedOperation := test.failedOperation
			var failures atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, operation, _ := strings.Cut(r.Header.Get("X-Amz-Target"), ".")
				if operation == failedOperation {
					failures.Add(1)
					w.Header().Set("Content-Type", "application/x-amz-json-1.1")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"denied"}`))
					return
				}
				var body string
				switch operation {
				case "": // STS uses the query protocol.
					w.Header().Set("Content-Type", "text/xml")
					body = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
				case "GetResource":
					body = `{"TypeName":"AWS::Logs::LogGroup","ResourceDescription":{"Identifier":"/test","Properties":"{\"LogGroupName\":\"/test\"}"}}`
				case "DescribeLogStreams":
					body = `{"logStreams":[{"logStreamName":"stream"}]}`
				default:
					assert.Fail(t, "unexpected AWS operation", "%s", operation)
					w.WriteHeader(http.StatusBadRequest)
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			t.Setenv("AWS_ENDPOINT_URL", server.URL)
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/credentials")

			cfg := plugin.Config{Context: context.Background(), Args: map[string]any{
				"regions":       []string{"us-east-1"},
				"resource-arn":  []string{"arn:aws:logs:us-east-1:123456789012:log-group:/test"},
				"output-dir":    t.TempDir(),
				test.checkpoint: "0001-01-01T00:00:00Z",
			}}
			mod := plugin.ModuleWrapper{Module: &AWSFindSecretsModule{}}
			out := pipeline.New[model.AurelianModel]()
			pipeline.Pipe(pipeline.From(cfg), mod.Run, out)
			_, err := out.Collect()
			require.Error(t, err)
			assert.Contains(t, err.Error(), failedOperation)
			assert.Positive(t, failures.Load())
		})
	}
}
