package dnstakeover

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"context"
	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckerCloudDispatch(t *testing.T) {
	saved := checkersByRecordType
	checkersByRecordType = map[string][]registeredChecker{}
	t.Cleanup(func() { checkersByRecordType = saved })
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
		mustRegister("CNAME", registration.name, func(ctx CheckContext, _ AzureDNSRecord, _ *pipeline.P[model.AurelianModel]) error {
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
			dispatcher := NewDNSTakeoverChecker(context.Background(), plugin.AzureCommonRecon{AzureReconBase: plugin.AzureReconBase{Env: env}}, nil)
			constructionLog := logs.String()
			var warning struct {
				Level   string
				Cloud   string
				Skipped []string `json:"checks"`
			}
			require.NoError(t, json.Unmarshal(logs.Bytes(), &warning), "exactly one warning per construction")
			assert.Equal(t, "WARN", warning.Level)
			assert.Equal(t, tc.cloud, warning.Cloud)
			assert.Equal(t, tc.skipped, warning.Skipped)
			for range 2 {
				calls = nil
				require.NoError(t, dispatcher.Check(AzureDNSRecord{Type: "CNAME"}, nil))
				assert.Equal(t, tc.wantCalls, calls)
			}
			assert.Equal(t, constructionLog, logs.String(), "do not repeat the warning for each resource")
		})
	}
}

func TestCheckerGovernmentRegistrations(t *testing.T) {
	assert.Equal(t, []string{"cdn-takeover", "frontdoor-takeover", "ns-delegation"}, unsupportedCheckers(azurecloud.Resolve("gcc-high")))
	assert.Empty(t, unsupportedCheckers(azurecloud.Resolve("")))
	var logs bytes.Buffer
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	NewDNSTakeoverChecker(context.Background(), plugin.AzureCommonRecon{AzureReconBase: plugin.AzureReconBase{Env: azurecloud.Resolve("")}}, nil)
	assert.Empty(t, logs.String(), "no warning when every capability is supported")
}
