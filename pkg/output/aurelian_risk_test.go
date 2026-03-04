package output

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAurelianRiskJSONSerialization(t *testing.T) {
	risk := AurelianRisk{Name: "public-aws-resource", Severity: RiskSeverityHigh, ImpactedARN: "arn:aws:s3:::example", Context: json.RawMessage(`{"is_public":true}`)}
	data, err := json.Marshal(risk)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"severity":"high"`)
	assert.Contains(t, string(data), `"impacted_arn":"arn:aws:s3:::example"`)
}
