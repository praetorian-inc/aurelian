package output

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeResult_ImplementsAurelianModel(t *testing.T) {
	var _ model.AurelianModel = AnalyzeResult{}
	var _ model.AurelianModel = &AnalyzeResult{}
}

func TestAnalyzeResult_JSONRoundTrip(t *testing.T) {
	resultsPayload := json.RawMessage(`{"matched":["s3:GetObject","s3:PutObject"]}`)

	r := AnalyzeResult{
		Module:  "expand-actions",
		Input:   "s3:*",
		Results: resultsPayload,
	}

	data, err := json.Marshal(r)
	require.NoError(t, err)

	var got AnalyzeResult
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, r.Module, got.Module)
	assert.Equal(t, r.Input, got.Input)
	assert.JSONEq(t, string(r.Results), string(got.Results))
}

func TestAnalyzeResult_JSONFieldNames(t *testing.T) {
	r := AnalyzeResult{
		Module:  "ip-lookup",
		Input:   "1.2.3.4",
		Results: json.RawMessage(`{"region":"us-east-1"}`),
	}

	data, err := json.Marshal(r)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "module")
	assert.Contains(t, raw, "input")
	assert.Contains(t, raw, "results")

	var module, input string
	require.NoError(t, json.Unmarshal(raw["module"], &module))
	require.NoError(t, json.Unmarshal(raw["input"], &input))

	assert.Equal(t, "ip-lookup", module)
	assert.Equal(t, "1.2.3.4", input)
}

func TestAnalyzeResult_NullResults(t *testing.T) {
	r := AnalyzeResult{
		Module:  "known-account",
		Input:   "123456789012",
		Results: nil,
	}

	data, err := json.Marshal(r)
	require.NoError(t, err)

	var got AnalyzeResult
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, r.Module, got.Module)
	assert.Equal(t, r.Input, got.Input)
}
