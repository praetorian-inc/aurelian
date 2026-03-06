package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	azappconfig "github.com/Azure/azure-sdk-for-go/sdk/data/azappconfig"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.appconfiguration/configurationstores", "app-config-keyvalues", extractAppConfigKeyValues)
}

func extractAppConfigKeyValues(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, _, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse App Configuration resource ID: %w", err)
	}

	storeName := segments["configurationStores"]
	if storeName == "" {
		return fmt.Errorf("no configurationStores segment in resource ID %s", r.ResourceID)
	}

	endpoint := fmt.Sprintf("https://%s.azconfig.io", storeName)
	client, err := azappconfig.NewClient(endpoint, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create App Configuration client: %w", err)
	}

	pager := client.NewListSettingsPager(azappconfig.SettingSelector{}, nil)
	pageNum := 0

	for pager.More() {
		pageNum++
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "app-config-keyvalues", r.ResourceID)
		}

		type kvPair struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}

		var pairs []kvPair
		for _, setting := range page.Settings {
			if setting.Key != nil && setting.Value != nil {
				pairs = append(pairs, kvPair{Key: *setting.Key, Value: *setting.Value})
			}
		}

		if len(pairs) == 0 {
			continue
		}

		content, err := json.Marshal(pairs)
		if err != nil {
			slog.Warn("failed to marshal App Config key-values", "store", storeName, "page", pageNum, "error", err)
			continue
		}

		label := fmt.Sprintf("AppConfig KeyValues (page %d)", pageNum)
		out.Send(output.ScanInputFromAzureResource(r, label, content))
	}

	return nil
}
