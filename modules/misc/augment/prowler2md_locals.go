package augment

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// LOCAL type
type Occurences [][]string

// LOCAL func
func getColumnIndex(header []string, columnName string) int {
	for i, name := range header {
		if name == columnName {
			return i
		}
	}
	return -1
}

var providerChecks = map[string][]string{
	"aws": {},
	"gcp": {},
	"azure": {
		"storage_infrastructure_encryption_is_enabled",
		"storage_ensure_private_endpoints_in_storage_accounts",
		"storage_blob_public_access_level_is_disabled",
		"storage_ensure_minimum_tls_version_12",
		"storage_default_network_access_rule_is_denied",
		"app_ftp_deployment_disabled",
		"app_ensure_using_http20",
		"app_ensure_auth_is_set_up",
		"entra_policy_restricts_user_consent_for_apps",
		"entra_policy_guest_invite_only_for_admin_roles",
		"entra_policy_default_users_cannot_create_security_groups",
		"entra_users_cannot_create_microsoft_365_groups",
		"monitor_diagnostic_setting_with_appropriate_categories",
		"monitor_diagnostic_settings_exists",
		"sqlserver_tde_encryption_enabled",
		"keyvault_private_endpoints",
		"keyvault_rbac_enabled",
		"keyvault_key_expiration_set_in_non_rbac",
	},
}

var providerHeaders = map[string][]string{
	"aws":   {"CHECK_ID", "RESOURCE_UID", "SEVERITY", "STATUS"},
	"gcp":   {"CHECK_ID", "ACCOUNT_UID", "RESOURCE_TYPE", "RESOURCE_UID", "REGION", "SEVERITY", "STATUS"},
	"azure": {"CHECK_ID", "SERVICE_NAME", "RESOURCE_UID", "REGION", "SEVERITY", "STATUS"},
}

// LOCAL Stage
func prowlerToMDTableStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.MarkdownTable {
	out := make(chan types.MarkdownTable)
	provider := strings.ToLower(types.GetOptionByName(options.ProviderType.Name, opts).Value)
	go func() {
		defer close(out)
		groupedData := make(map[string]Occurences)
		for inputCSV := range in {
			file, err := os.Open(inputCSV)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Errorf("error opening CSV %s. [%w]", inputCSV, err).Error())
				continue
			}
			reader := csv.NewReader(file)
			reader.Comma = ';'
			header, err := reader.Read()
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Errorf("error reading CSV %s. [%w]", inputCSV, err).Error())
				continue
			}
			indexes := []int{}
			for _, column := range providerHeaders[provider] {
				indexes = append(indexes, getColumnIndex(header, column))
			}

			for {
				row, err := reader.Read()
				if err != nil {
					// logs.ConsoleLogger().Error(fmt.Errorf("error reading row in CSV %s. [%w]", inputCSV, err))
					break
				}
				// STATUS is the last index
				status := row[indexes[len(indexes)-1]]
				if strings.ToUpper(status) == "FAIL" {
					// TODO: RE-ENABLE WHEN PROVIDER-CHECKS ARE READY
					// if !helpers.ElemInStringSlice(row[indexes[0]], providerChecks[provider]) {
					// 	continue
					// }
					filteredRow := []string{}
					// Looping over everything except STATUS
					for i := 0; i < len(indexes)-1; i++ {
						filteredRow = append(filteredRow, row[indexes[i]])
					}
					// CheckID is at index 0
					if _, exists := groupedData[filteredRow[0]]; !exists {
						groupedData[filteredRow[0]] = Occurences{filteredRow}
					} else {
						groupedData[filteredRow[0]] = append(groupedData[filteredRow[0]], filteredRow)
					}
				}
			}
			file.Close()
		}
		headers := []string{}
		for i := 0; i < len(providerHeaders[provider])-1; i++ {
			headers = append(headers, providerHeaders[provider][i])
		}
		tableToWrite := types.MarkdownTable{
			Headers: headers,
			Rows:    [][]string{},
		}
		for _, occurences := range groupedData {
			for _, val := range occurences {
				tableToWrite.Rows = append(tableToWrite.Rows, val)
			}
		}
		out <- tableToWrite
	}()
	return out
}
