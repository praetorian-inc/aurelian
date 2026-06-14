package analyze

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		want       output.RiskSeverity
	}{
		{"empty defaults high", nil, output.RiskSeverityHigh},
		{"single low", []string{"low"}, output.RiskSeverityLow},
		{"single medium", []string{"medium"}, output.RiskSeverityMedium},
		{"single high", []string{"high"}, output.RiskSeverityHigh},
		{"max of mixed", []string{"low", "high", "medium"}, output.RiskSeverityHigh},
		{"low and medium", []string{"low", "medium"}, output.RiskSeverityMedium},
		{"case insensitive", []string{"LOW", "Medium"}, output.RiskSeverityMedium},
		{"unknown defaults high", []string{"bogus"}, output.RiskSeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, maxSeverity(tt.severities))
		})
	}
}

func TestRiskFromRecord(t *testing.T) {
	t.Run("well-formed admin path", func(t *testing.T) {
		rec := map[string]any{
			"attacker_arn":      "arn:aws:iam::111:user/attacker",
			"target_arn":        "arn:aws:iam::111:role/admin",
			"methods":           []any{"iam:PassRole+lambda:CreateFunction", "iam:CreateAccessKey"},
			"method_severities": []any{"high", "low"},
			// methods_per_hop: every parallel method available per hop (multigraph collapse).
			"methods_per_hop": []any{
				[]any{"iam:PassRole+lambda:CreateFunction", "iam:PassRole+ec2:RunInstances"},
				[]any{"iam:CreateAccessKey"},
			},
			"hop_count": int64(2),
		}

		risk, ok := riskFromRecord(rec)
		require.True(t, ok)
		assert.Equal(t, privescRiskName, risk.Name)
		assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
		assert.Equal(t, "arn:aws:iam::111:user/attacker", risk.ImpactedResourceID)
		assert.Equal(t,
			"arn:aws:iam::111:user/attacker|arn:aws:iam::111:role/admin|iam:PassRole+lambda:CreateFunction>iam:CreateAccessKey",
			risk.DeduplicationID)

		var ctx struct {
			AttackerARN   string     `json:"attacker_arn"`
			TargetARN     string     `json:"target_arn"`
			Methods       []string   `json:"methods"`
			MethodsPerHop [][]string `json:"methods_per_hop"`
			HopCount      int64      `json:"hop_count"`
			PathSeverity  string     `json:"path_severity"`
		}
		require.NoError(t, json.Unmarshal(risk.Context, &ctx))
		assert.Equal(t, "arn:aws:iam::111:user/attacker", ctx.AttackerARN)
		assert.Equal(t, "arn:aws:iam::111:role/admin", ctx.TargetARN)
		assert.Equal(t, []string{"iam:PassRole+lambda:CreateFunction", "iam:CreateAccessKey"}, ctx.Methods)
		assert.Equal(t, [][]string{
			{"iam:PassRole+lambda:CreateFunction", "iam:PassRole+ec2:RunInstances"},
			{"iam:CreateAccessKey"},
		}, ctx.MethodsPerHop)
		assert.Equal(t, int64(2), ctx.HopCount)
		assert.Equal(t, "high", ctx.PathSeverity)
	})

	t.Run("hop_count as float64 from json round-trip", func(t *testing.T) {
		rec := map[string]any{
			"attacker_arn":      "arn:aws:iam::111:user/a",
			"target_arn":        "arn:aws:iam::111:role/admin",
			"methods":           []any{"iam:CreateAccessKey"},
			"method_severities": []any{"low"},
			"hop_count":         float64(1),
		}
		risk, ok := riskFromRecord(rec)
		require.True(t, ok)
		assert.Equal(t, output.RiskSeverityLow, risk.Severity)
		var ctx struct {
			HopCount int64 `json:"hop_count"`
		}
		require.NoError(t, json.Unmarshal(risk.Context, &ctx))
		assert.Equal(t, int64(1), ctx.HopCount)
	})

	t.Run("empty severities default high", func(t *testing.T) {
		rec := map[string]any{
			"attacker_arn":      "arn:aws:iam::111:user/a",
			"target_arn":        "arn:aws:iam::111:role/admin",
			"methods":           []any{"iam:CreateAccessKey"},
			"method_severities": []any{},
			"hop_count":         int64(1),
		}
		risk, ok := riskFromRecord(rec)
		require.True(t, ok)
		assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	})

	t.Run("missing attacker arn dropped", func(t *testing.T) {
		_, ok := riskFromRecord(map[string]any{
			"target_arn": "arn:aws:iam::111:role/admin",
			"methods":    []any{"iam:CreateAccessKey"},
		})
		assert.False(t, ok)
	})

	t.Run("empty methods dropped", func(t *testing.T) {
		_, ok := riskFromRecord(map[string]any{
			"attacker_arn": "arn:aws:iam::111:user/a",
			"target_arn":   "arn:aws:iam::111:role/admin",
			"methods":      []any{},
		})
		assert.False(t, ok)
	})

	t.Run("dedup id stable across identical records", func(t *testing.T) {
		rec := map[string]any{
			"attacker_arn":      "arn:aws:iam::111:user/a",
			"target_arn":        "arn:aws:iam::111:role/admin",
			"methods":           []any{"m1", "m2"},
			"method_severities": []any{"high"},
			"hop_count":         int64(2),
		}
		r1, ok1 := riskFromRecord(rec)
		r2, ok2 := riskFromRecord(rec)
		require.True(t, ok1)
		require.True(t, ok2)
		assert.NotEmpty(t, r1.DeduplicationID)
		assert.Equal(t, r1.DeduplicationID, r2.DeduplicationID)
	})
}
