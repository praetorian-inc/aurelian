// modules/recon/azure/public_access.go
package reconaz

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// PublicResourceSummary combines all resource types into a single result structure
type PublicResourceSummary struct {
	StorageAccounts      []*stages.AzureStorageAccountDetail `json:"storageAccounts,omitempty"`
	AppServices          []*stages.AppServiceDetail          `json:"appServices,omitempty"`
	SqlResources         []*stages.SqlServerDetail           `json:"sqlResources,omitempty"`
	VirtualMachines      []*stages.VirtualMachineDetail      `json:"virtualMachines,omitempty"`
	ContainerRegistries  []*stages.ContainerRegistryDetail   `json:"containerRegistries,omitempty"`
	CosmosDbAccounts     []*stages.CosmosDBDetail            `json:"cosmosDbAccounts,omitempty"`
	RedisCaches          []*stages.RedisCacheDetail          `json:"redisCaches,omitempty"`
	ServiceBusNamespaces []*stages.ServiceBusDetail          `json:"serviceBusNamespaces,omitempty"`
}

func NewAzurePublicAccess(opts []*types.Option) (<-chan string, stages.Stage[string, types.Result], error) {
	pipeline, err := stages.ChainStages[string, types.Result](
		ProcessAllResourceTypes,
		FormatPublicAccessOutput,
	)

	if err != nil {
		return nil, nil, err
	}

	subscriptionOpt := options.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value

	if strings.EqualFold(subscriptionOpt, "all") {
		ctx := context.WithValue(context.Background(), "metadata", AzurePublicAccessMetadata)
		subscriptions, err := helpers.ListSubscriptions(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		return stages.Generator(subscriptions), pipeline, nil
	}

	return stages.Generator([]string{subscriptionOpt}), pipeline, nil
}

// ProcessAllResourceTypes checks all resource types for public access
func ProcessAllResourceTypes(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *PublicResourceSummary {
	logger := logs.NewStageLogger(ctx, opts, "ProcessAllResourceTypes")
	out := make(chan *PublicResourceSummary)

	go func() {
		defer close(out)

		for subscription := range in {
			summary := &PublicResourceSummary{}

			// Create input channel for each stage
			subChan := make(chan string, 1)
			subChan <- subscription
			close(subChan)

			// Process storage accounts
			if storageAccounts := <-stages.AzureStorageAccountStage(ctx, opts, subChan); len(storageAccounts) > 0 {
				summary.StorageAccounts = storageAccounts
				logger.Debug("Found publicly accessible storage accounts", "count", len(storageAccounts))
			}

			// Process app services
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if appServices := <-stages.AzureAppServiceStage(ctx, opts, subChan); len(appServices) > 0 {
				summary.AppServices = appServices
				logger.Debug("Found publicly accessible app services", "count", len(appServices))
			}

			// Process SQL resources
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if sqlResources := <-stages.AzureSqlStage(ctx, opts, subChan); len(sqlResources) > 0 {
				summary.SqlResources = sqlResources
				logger.Debug("Found publicly accessible SQL resources", "count", len(sqlResources))
			}

			// Process VMs
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if vms := <-stages.AzureVMStage(ctx, opts, subChan); len(vms) > 0 {
				summary.VirtualMachines = vms
				logger.Debug("Found publicly accessible VMs", "count", len(vms))
			}

			// Process container registries
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if registries := <-stages.AzureContainerRegistryStage(ctx, opts, subChan); len(registries) > 0 {
				summary.ContainerRegistries = registries
				logger.Debug("Found publicly accessible container registries", "count", len(registries))
			}

			// Process Cosmos DB
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if cosmosAccounts := <-stages.AzureCosmosDBStage(ctx, opts, subChan); len(cosmosAccounts) > 0 {
				summary.CosmosDbAccounts = cosmosAccounts
				logger.Debug("Found publicly accessible Cosmos DB accounts", "count", len(cosmosAccounts))
			}

			// Process Redis caches
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if redisCaches := <-stages.AzureRedisCacheStage(ctx, opts, subChan); len(redisCaches) > 0 {
				summary.RedisCaches = redisCaches
				logger.Debug("Found publicly accessible Redis caches", "count", len(redisCaches))
			}

			// Process Service Bus namespaces
			subChan = make(chan string, 1)
			subChan <- subscription
			close(subChan)
			if serviceBus := <-stages.AzureServiceBusStage(ctx, opts, subChan); len(serviceBus) > 0 {
				summary.ServiceBusNamespaces = serviceBus
				logger.Debug("Found publicly accessible Service Bus namespaces", "count", len(serviceBus))
			}

			out <- summary
		}
	}()

	return out
}

var AzurePublicAccessMetadata = modules.Metadata{
	Id:          "public-access",
	Name:        "Public Access Scanner",
	Description: "Detect publicly accessible Azure resources including storage accounts, app services, SQL databases, VMs, and more",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
	},
}

var AzurePublicAccessOptions = []*types.Option{
	&options.AzureSubscriptionOpt,
	&options.AzureWorkerCountOpt,
	options.WithDefaultValue(
		*options.WithRequired(
			options.FileNameOpt, false),
		""),
}

var AzurePublicAccessOutputProviders = []func(options []*types.Option) types.OutputProvider{
	op.NewJsonFileProvider,
	op.NewMarkdownFileProvider,
}

// FormatPublicAccessOutput formats the scan results for output
func FormatPublicAccessOutput(ctx context.Context, opts []*types.Option, in <-chan *PublicResourceSummary) <-chan types.Result {
	out := make(chan types.Result)

	go func() {
		defer close(out)

		for summary := range in {
			// Generate base filename
			baseFilename := ""
			providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
			if len(providedFilename) == 0 {
				timestamp := strconv.FormatInt(time.Now().Unix(), 10)
				baseFilename = fmt.Sprintf("public-access-%s", timestamp)
			} else {
				baseFilename = providedFilename
			}

			// Output JSON
			out <- types.NewResult(
				modules.Azure,
				"public-access",
				summary,
				types.WithFilename(baseFilename+".json"),
			)

			// Create markdown table
			table := types.MarkdownTable{
				TableHeading: fmt.Sprintf("# Publicly Accessible Azure Resources\n\n"+
					"## Resource Summary\n"+
					"- Storage Accounts: %d\n"+
					"- App Services: %d\n"+
					"- SQL Resources: %d\n"+
					"- Virtual Machines: %d\n"+
					"- Container Registries: %d\n"+
					"- Cosmos DB Accounts: %d\n"+
					"- Redis Caches: %d\n"+
					"- Service Bus Namespaces: %d\n\n"+
					"## Detailed Findings",
					len(summary.StorageAccounts),
					len(summary.AppServices),
					len(summary.SqlResources),
					len(summary.VirtualMachines),
					len(summary.ContainerRegistries),
					len(summary.CosmosDbAccounts),
					len(summary.RedisCaches),
					len(summary.ServiceBusNamespaces)),
				Headers: []string{
					"Resource Type",
					"Name",
					"Location",
					"Access Type",
					"Details",
				},
				Rows: make([][]string, 0),
			}

			// Add storage accounts to table
			addResourceToTable(&table, "Storage Account", summary.StorageAccounts, func(sa *stages.AzureStorageAccountDetail) []string {
				return []string{
					sa.Name,
					sa.Location,
					sa.PublicNetworkAccess,
					fmt.Sprintf("Default Action: %s", sa.DefaultAction),
				}
			})

			// Add app services to table
			addResourceToTable(&table, "App Service", summary.AppServices, func(app *stages.AppServiceDetail) []string {
				return []string{
					app.Name,
					app.Location,
					fmt.Sprintf("Public: %v", app.PublicNetworkAccess),
					fmt.Sprintf("Kind: %s", app.Kind),
				}
			})

			// Add SQL resources to table
			addResourceToTable(&table, "SQL Resource", summary.SqlResources, func(sql *stages.SqlServerDetail) []string {
				return []string{
					sql.Name,
					sql.Location,
					sql.PublicNetworkAccess,
					fmt.Sprintf("Scope: %s, TLS: %s", sql.Scope, sql.MinimalTlsVersion),
				}
			})

			// Add virtual machines to table
			addResourceToTable(&table, "Virtual Machine", summary.VirtualMachines, func(vm *stages.VirtualMachineDetail) []string {
				return []string{
					vm.Name,
					vm.Location,
					vm.PublicIP,
					fmt.Sprintf("OS: %s, Open Ports: %s", vm.OsType, vm.OpenPorts),
				}
			})

			// Add container registries to table
			addResourceToTable(&table, "Container Registry", summary.ContainerRegistries, func(acr *stages.ContainerRegistryDetail) []string {
				return []string{
					acr.Name,
					acr.Location,
					acr.PublicNetworkAccess,
					fmt.Sprintf("SKU: %s, Admin: %v", acr.Sku, acr.AdminEnabled),
				}
			})

			// Add Cosmos DB accounts to table
			addResourceToTable(&table, "Cosmos DB", summary.CosmosDbAccounts, func(cosmos *stages.CosmosDBDetail) []string {
				return []string{
					cosmos.Name,
					cosmos.Location,
					cosmos.PublicNetworkAccess,
					fmt.Sprintf("Kind: %s, Free Tier: %v", cosmos.Kind, cosmos.EnableFreeTier),
				}
			})

			// Add Redis caches to table
			addResourceToTable(&table, "Redis Cache", summary.RedisCaches, func(redis *stages.RedisCacheDetail) []string {
				return []string{
					redis.Name,
					redis.Location,
					redis.PublicNetworkAccess,
					fmt.Sprintf("SKU: %s, Non-SSL: %v", redis.Sku, redis.EnableNonSslPort),
				}
			})

			// Add Service Bus namespaces to table
			addResourceToTable(&table, "Service Bus", summary.ServiceBusNamespaces, func(sb *stages.ServiceBusDetail) []string {
				return []string{
					sb.Name,
					sb.Location,
					sb.PublicNetworkAccess,
					fmt.Sprintf("SKU: %s, Endpoint: %s", sb.Sku, sb.Endpoint),
				}
			})

			out <- types.NewResult(
				modules.Azure,
				"public-access",
				table,
				types.WithFilename(baseFilename+".md"),
			)
		}
	}()

	return out
}

// Helper function to add resources to the markdown table
func addResourceToTable[T any](table *types.MarkdownTable, resourceType string, resources []T, detailsFunc func(T) []string) {
	for _, resource := range resources {
		details := detailsFunc(resource)
		table.Rows = append(table.Rows, append([]string{resourceType}, details...))
	}
}
