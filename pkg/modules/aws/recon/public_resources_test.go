package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskFromResult_NameAndDeduplicationID(t *testing.T) {
	tests := []struct {
		name             string
		resourceType     string
		accessLevel      output.AccessLevel
		wantRiskName     string
		wantDedupeID     string
		wantSeverity     output.RiskSeverity
	}{
		{
			name:         "lambda function - public",
			resourceType: "AWS::Lambda::Function",
			accessLevel:  output.AccessLevelPublic,
			wantRiskName: "public-aws-resource-lambda-function",
			wantDedupeID: "AWS::Lambda::Function",
			wantSeverity: output.RiskSeverityHigh,
		},
		{
			name:         "s3 bucket - public",
			resourceType: "AWS::S3::Bucket",
			accessLevel:  output.AccessLevelPublic,
			wantRiskName: "public-aws-resource-s3-bucket",
			wantDedupeID: "AWS::S3::Bucket",
			wantSeverity: output.RiskSeverityHigh,
		},
		{
			name:         "ec2 instance - needs triage",
			resourceType: "AWS::EC2::Instance",
			accessLevel:  output.AccessLevelNeedsTriage,
			wantRiskName: "public-aws-resource-ec2-instance",
			wantDedupeID: "AWS::EC2::Instance",
			wantSeverity: output.RiskSeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := publicaccess.PublicAccessResult{
				AWSResource: &output.AWSResource{
					ResourceType: tt.resourceType,
					ResourceID:   "arn:aws:test:us-east-1:123456789012:test/test-resource",
					ARN:          "arn:aws:test:us-east-1:123456789012:test/test-resource",
					AccessLevel:  tt.accessLevel,
				},
			}

			out := pipeline.New[model.AurelianModel]()
			go func() {
				defer out.Close()
				riskFromResult(result, out)
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1)

			risk := items[0].(output.AurelianRisk)
			assert.Equal(t, tt.wantRiskName, risk.Name)
			assert.Equal(t, tt.wantDedupeID, risk.DeduplicationID)
			assert.Equal(t, tt.wantSeverity, risk.Severity)
		})
	}
}
