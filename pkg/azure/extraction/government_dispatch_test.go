package extraction

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractorCloudDispatch(t *testing.T) {
	saved := extractorsByType
	extractorsByType = map[string][]registeredExtractor{}
	t.Cleanup(func() { extractorsByType = saved })
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })

	var calls []string
	for _, registration := range []struct {
		name   string
		clouds []string
	}{
		{"all", nil},
		{"empty", []string{}},
		{"both", []string{azurecloud.Public, azurecloud.Government}},
		{"z-public", []string{azurecloud.Public}},
		{"a-public", []string{azurecloud.Public}},
		{"government", []string{azurecloud.Government}},
	} {
		mustRegister("test/resources", registration.name, func(ctx extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
			assert.Contains(t, []string{azurecloud.Public, azurecloud.Government}, ctx.Env.Name)
			calls = append(calls, registration.name)
			return nil
		}, registration.clouds...)
	}

	for _, tc := range []struct {
		cloud              string
		wantCalls, skipped []string
	}{
		{azurecloud.Public, []string{"all", "empty", "both", "z-public", "a-public"}, []string{"government"}},
		{azurecloud.Government, []string{"all", "empty", "both", "government"}, []string{"a-public", "z-public"}},
	} {
		t.Run(tc.cloud, func(t *testing.T) {
			var logs bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			env := azurecloud.Resolve(tc.cloud)
			dispatcher := NewAzureExtractor(nil, env)
			constructionLog := logs.String()
			var warning struct {
				Level   string
				Cloud   string
				Skipped []string `json:"extractors"`
			}
			require.NoError(t, json.Unmarshal(logs.Bytes(), &warning), "exactly one warning per construction")
			assert.Equal(t, "WARN", warning.Level)
			assert.Equal(t, tc.cloud, warning.Cloud)
			assert.Equal(t, tc.skipped, warning.Skipped)
			for range 2 {
				calls = nil
				require.NoError(t, dispatcher.Extract(output.AzureResource{ResourceType: "Test/Resources"}, nil))
				assert.Equal(t, tc.wantCalls, calls)
			}
			assert.Equal(t, constructionLog, logs.String(), "do not repeat the warning for each resource")
		})
	}
}

func TestExtractorGovernmentRegistrations(t *testing.T) {
	assert.Equal(t, []string{"blueprint-artifacts", "digitaltwins-properties"}, unsupportedExtractors(azurecloud.Resolve("gcc-high")))
	assert.Empty(t, unsupportedExtractors(azurecloud.Resolve("")))
	var logs bytes.Buffer
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	NewAzureExtractor(nil, azurecloud.Resolve(""))
	assert.Empty(t, logs.String(), "no warning when every capability is supported")
}
