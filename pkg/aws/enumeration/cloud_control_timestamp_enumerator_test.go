package enumeration

import (
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Guard keys assets by ARN and stores Properties verbatim, and extractors read
// CloudControl identifiers: the dispatcher's output for the stamped types must
// equal plain CloudControl's in everything but LastModified.
func TestNewEnumerator_StampedTypesMatchCloudControlExceptLastModified(t *testing.T) {
	stamp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		resourceType string
		arn          string
		description  string
		stub         func(t *testing.T, fake *fakeAWS)
	}{
		{
			resourceType: "AWS::EC2::Instance",
			arn:          "arn:aws:ec2:us-east-1:123456789012:instance/i-aaa",
			description:  ec2Instance("i-aaa"),
			stub: func(_ *testing.T, fake *fakeAWS) {
				fake.reply("DescribeInstances", ec2DescribeInstances(map[string]string{"i-aaa": stamp.Format(time.RFC3339)}))
			},
		},
		{
			resourceType: "AWS::Logs::LogGroup",
			arn:          "arn:aws:logs:us-east-1:123456789012:log-group:/app/api",
			description:  logGroup("/app/api"),
			stub: func(_ *testing.T, fake *fakeAWS) {
				fake.reply("DescribeLogStreams", logStreams(millis(stamp)))
			},
		},
		{
			resourceType: "AWS::StepFunctions::StateMachine",
			arn:          sfnOrders,
			description:  sfnStateMachine(sfnOrders),
			stub: func(t *testing.T, fake *fakeAWS) {
				fake.on("ListExecutions", sfnExecutionsByMachine(t, map[string]string{sfnOrders: sfnExecution(epoch(stamp), "")}))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.resourceType, func(t *testing.T) {
			fake := newFakeAWS(t)
			fake.reply("ListResources", ccListResources(tc.resourceType, tc.description))
			fake.reply("GetResource", ccGetResource(tc.resourceType, tc.description))
			tc.stub(t, fake)
			provider := newFakeProvider(fake, "us-east-1")

			dispatcher := NewEnumeratorWithProvider(provider.AWSCommonRecon, provider, NewSkipReport())
			plain := newFakeCloudControl(provider, NewSkipReport())

			for _, identifier := range []string{tc.resourceType, tc.arn} {
				stamped, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
					return dispatcher.List(identifier, out)
				})
				require.NoError(t, err)
				want, err := collectFakeResources(t, func(out *pipeline.P[output.AWSResource]) error {
					return plain.List(identifier, out)
				})
				require.NoError(t, err)

				require.Len(t, stamped, 1, identifier)
				require.Len(t, want, 1, identifier)
				require.NotNil(t, stamped[0].LastModified, "%s: dispatcher must route to the timestamping enumerator", identifier)
				assert.Equal(t, stamp, stamped[0].LastModified.UTC(), identifier)

				stamped[0].LastModified = nil
				assert.Equal(t, want[0], stamped[0], "%s: everything except LastModified must equal CloudControl's output", identifier)
			}
		})
	}
}
