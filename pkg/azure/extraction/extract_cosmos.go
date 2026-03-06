package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"
	armcosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const (
	// maxCosmosDocSize caps individual document size at 1 MB.
	maxCosmosDocSize = 1 << 20
)

// configCollectionNames are container names that likely hold configuration data.
var configCollectionNames = map[string]bool{
	"settings":      true,
	"config":        true,
	"secrets":       true,
	"configuration": true,
}

func init() {
	mustRegister("microsoft.documentdb/databaseaccounts", "cosmos-storedprocs", extractCosmosStoredProcs)
	mustRegister("microsoft.documentdb/databaseaccounts", "cosmos-triggers", extractCosmosTriggers)
	mustRegister("microsoft.documentdb/databaseaccounts", "cosmos-udfs", extractCosmosUDFs)
	mustRegister("microsoft.documentdb/databaseaccounts", "cosmos-config-docs", extractCosmosConfigDocs)
}

// newCosmosSQLClient creates a Cosmos ARM SQLResourcesClient for enumerating databases, containers,
// stored procs, triggers, and UDFs via the management plane.
func newCosmosSQLClient(ctx extractContext, subscriptionID string) (*armcosmos.SQLResourcesClient, error) {
	return armcosmos.NewSQLResourcesClient(subscriptionID, ctx.Cred, nil)
}

// cosmosDBContainers enumerates all SQL databases and containers for a Cosmos DB account
// via the ARM management plane. Returns pairs of (databaseName, containerName).
func cosmosDBContainers(ctx extractContext, sqlClient *armcosmos.SQLResourcesClient, resourceGroup, accountName string) ([][2]string, error) {
	var result [][2]string

	dbPager := sqlClient.NewListSQLDatabasesPager(resourceGroup, accountName, nil)
	for dbPager.More() {
		dbPage, err := dbPager.NextPage(ctx.Context)
		if err != nil {
			return nil, err
		}

		for _, db := range dbPage.Value {
			if db.Properties == nil || db.Properties.Resource == nil || db.Properties.Resource.ID == nil {
				continue
			}
			dbName := *db.Properties.Resource.ID

			containerPager := sqlClient.NewListSQLContainersPager(resourceGroup, accountName, dbName, nil)
			for containerPager.More() {
				containerPage, err := containerPager.NextPage(ctx.Context)
				if err != nil {
					slog.Warn("failed to list Cosmos containers", "db", dbName, "error", err)
					break
				}
				for _, c := range containerPage.Value {
					if c.Properties == nil || c.Properties.Resource == nil || c.Properties.Resource.ID == nil {
						continue
					}
					result = append(result, [2]string{dbName, *c.Properties.Resource.ID})
				}
			}
		}
	}

	return result, nil
}

func extractCosmosStoredProcs(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Cosmos DB resource ID: %w", err)
	}

	accountName := segments["databaseAccounts"]
	if accountName == "" {
		return fmt.Errorf("no databaseAccounts segment in resource ID %s", r.ResourceID)
	}

	sqlClient, err := newCosmosSQLClient(ctx, r.SubscriptionID)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos SQL client: %w", err)
	}

	containers, err := cosmosDBContainers(ctx, sqlClient, resourceGroup, accountName)
	if err != nil {
		return handleExtractError(err, "cosmos-storedprocs", r.ResourceID)
	}

	for _, dc := range containers {
		dbName, containerName := dc[0], dc[1]

		sprocPager := sqlClient.NewListSQLStoredProceduresPager(resourceGroup, accountName, dbName, containerName, nil)
		for sprocPager.More() {
			page, err := sprocPager.NextPage(ctx.Context)
			if err != nil {
				slog.Warn("failed to list stored procedures", "db", dbName, "container", containerName, "error", err)
				break
			}

			for _, sproc := range page.Value {
				if sproc.Properties == nil || sproc.Properties.Resource == nil {
					continue
				}
				res := sproc.Properties.Resource
				sprocName := ""
				if res.ID != nil {
					sprocName = *res.ID
				}

				body := ""
				if res.Body != nil {
					body = *res.Body
				}
				if body == "" {
					continue
				}

				label := fmt.Sprintf("CosmosDB StoredProc: %s/%s/%s", dbName, containerName, sprocName)
				out.Send(output.ScanInputFromAzureResource(r, label, []byte(body)))
			}
		}
	}

	return nil
}

func extractCosmosTriggers(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Cosmos DB resource ID: %w", err)
	}

	accountName := segments["databaseAccounts"]
	if accountName == "" {
		return fmt.Errorf("no databaseAccounts segment in resource ID %s", r.ResourceID)
	}

	sqlClient, err := newCosmosSQLClient(ctx, r.SubscriptionID)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos SQL client: %w", err)
	}

	containers, err := cosmosDBContainers(ctx, sqlClient, resourceGroup, accountName)
	if err != nil {
		return handleExtractError(err, "cosmos-triggers", r.ResourceID)
	}

	for _, dc := range containers {
		dbName, containerName := dc[0], dc[1]

		triggerPager := sqlClient.NewListSQLTriggersPager(resourceGroup, accountName, dbName, containerName, nil)
		for triggerPager.More() {
			page, err := triggerPager.NextPage(ctx.Context)
			if err != nil {
				slog.Warn("failed to list triggers", "db", dbName, "container", containerName, "error", err)
				break
			}

			for _, trigger := range page.Value {
				if trigger.Properties == nil || trigger.Properties.Resource == nil {
					continue
				}
				res := trigger.Properties.Resource
				triggerName := ""
				if res.ID != nil {
					triggerName = *res.ID
				}

				body := ""
				if res.Body != nil {
					body = *res.Body
				}
				if body == "" {
					continue
				}

				label := fmt.Sprintf("CosmosDB Trigger: %s/%s/%s", dbName, containerName, triggerName)
				out.Send(output.ScanInputFromAzureResource(r, label, []byte(body)))
			}
		}
	}

	return nil
}

func extractCosmosUDFs(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Cosmos DB resource ID: %w", err)
	}

	accountName := segments["databaseAccounts"]
	if accountName == "" {
		return fmt.Errorf("no databaseAccounts segment in resource ID %s", r.ResourceID)
	}

	sqlClient, err := newCosmosSQLClient(ctx, r.SubscriptionID)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos SQL client: %w", err)
	}

	containers, err := cosmosDBContainers(ctx, sqlClient, resourceGroup, accountName)
	if err != nil {
		return handleExtractError(err, "cosmos-udfs", r.ResourceID)
	}

	for _, dc := range containers {
		dbName, containerName := dc[0], dc[1]

		udfPager := sqlClient.NewListSQLUserDefinedFunctionsPager(resourceGroup, accountName, dbName, containerName, nil)
		for udfPager.More() {
			page, err := udfPager.NextPage(ctx.Context)
			if err != nil {
				slog.Warn("failed to list UDFs", "db", dbName, "container", containerName, "error", err)
				break
			}

			for _, udf := range page.Value {
				if udf.Properties == nil || udf.Properties.Resource == nil {
					continue
				}
				res := udf.Properties.Resource
				udfName := ""
				if res.ID != nil {
					udfName = *res.ID
				}

				body := ""
				if res.Body != nil {
					body = *res.Body
				}
				if body == "" {
					continue
				}

				label := fmt.Sprintf("CosmosDB UDF: %s/%s/%s", dbName, containerName, udfName)
				out.Send(output.ScanInputFromAzureResource(r, label, []byte(body)))
			}
		}
	}

	return nil
}

func extractCosmosConfigDocs(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, _, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Cosmos DB resource ID: %w", err)
	}

	accountName := segments["databaseAccounts"]
	if accountName == "" {
		return fmt.Errorf("no databaseAccounts segment in resource ID %s", r.ResourceID)
	}

	endpoint := fmt.Sprintf("https://%s.documents.azure.com:443/", accountName)
	client, err := azcosmos.NewClient(endpoint, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos data-plane client: %w", err)
	}

	// Enumerate databases via data-plane query.
	dbPager := client.NewQueryDatabasesPager("SELECT * FROM c", nil)
	for dbPager.More() {
		dbPage, err := dbPager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "cosmos-config-docs", r.ResourceID)
		}

		for _, db := range dbPage.Databases {
			dbName := db.ID

			dbClient, err := client.NewDatabase(dbName)
			if err != nil {
				slog.Warn("failed to get Cosmos database client", "db", dbName, "error", err)
				continue
			}

			containerPager := dbClient.NewQueryContainersPager("SELECT * FROM c", nil)
			for containerPager.More() {
				containerPage, err := containerPager.NextPage(ctx.Context)
				if err != nil {
					slog.Warn("failed to list Cosmos containers", "db", dbName, "error", err)
					break
				}

				for _, container := range containerPage.Containers {
					containerName := container.ID
					if !configCollectionNames[containerName] {
						continue
					}

					containerClient, err := client.NewContainer(dbName, containerName)
					if err != nil {
						slog.Warn("failed to get Cosmos container client", "db", dbName, "container", containerName, "error", err)
						continue
					}

					queryConfigDocs(ctx, r, containerClient, dbName, containerName, out)
				}
			}
		}
	}

	return nil
}

func queryConfigDocs(ctx extractContext, r output.AzureResource, containerClient *azcosmos.ContainerClient, dbName, containerName string, out *pipeline.P[output.ScanInput]) {
	query := "SELECT TOP 50 * FROM c"
	// Use a cross-partition query by providing an empty partition key.
	crossPartition := true
	queryPager := containerClient.NewQueryItemsPager(query, azcosmos.NewPartitionKey(), &azcosmos.QueryOptions{
		EnableCrossPartitionQuery: &crossPartition,
	})

	for queryPager.More() {
		page, err := queryPager.NextPage(ctx.Context)
		if err != nil {
			slog.Warn("failed to query config docs", "db", dbName, "container", containerName, "error", err)
			return
		}

		for _, item := range page.Items {
			if len(item) > maxCosmosDocSize {
				slog.Debug("skipping large Cosmos doc", "db", dbName, "container", containerName, "size", len(item))
				continue
			}
			if len(item) == 0 {
				continue
			}
		}

		// Marshal all items from this page together.
		if len(page.Items) > 0 {
			content, err := json.Marshal(page.Items)
			if err != nil {
				slog.Warn("failed to marshal config docs", "db", dbName, "container", containerName, "error", err)
				continue
			}
			label := fmt.Sprintf("CosmosDB ConfigDoc: %s/%s", dbName, containerName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}
}
