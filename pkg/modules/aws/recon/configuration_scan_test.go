package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectRisks(t *testing.T, m *AWSConfigurationScanModule, r output.AWSResource) []output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, m.runChecks(r, out))
	}()
	results, err := out.Collect()
	require.NoError(t, err)
	var risks []output.AurelianRisk
	for _, x := range results {
		if risk, ok := x.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}
	return risks
}

func TestConfigurationScan_RunChecks_Dispatch(t *testing.T) {
	m := &AWSConfigurationScanModule{}

	t.Run("matching type + non-compliant -> risk", func(t *testing.T) {
		risks := collectRisks(t, m, output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-abc", ARN: "arn:aws:ec2:us-east-1:1:instance/i-abc",
			Properties: map[string]any{"MetadataHttpTokens": "optional", "MetadataHttpEndpoint": "enabled", "InstanceStateName": "running"},
		})
		require.Len(t, risks, 1)
		assert.Equal(t, "ec2-imdsv1-enabled", risks[0].Name)
	})

	t.Run("unrelated resource type -> no risk", func(t *testing.T) {
		risks := collectRisks(t, m, output.AWSResource{
			ResourceType: "AWS::S3::Bucket", ResourceID: "b", Properties: map[string]any{},
		})
		assert.Empty(t, risks)
	})
}

func TestConfigurationScan_Metadata(t *testing.T) {
	m := &AWSConfigurationScanModule{}
	assert.Equal(t, "configuration-scan", m.ID())
	assert.Equal(t, []string{"AWS::EC2::Instance"}, m.SupportedResourceTypes())
}
