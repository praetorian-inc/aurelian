package reconaz

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AzureSummary struct {
	modules.BaseModule
}

var AzureSummaryOptions = []*types.Option{
	&options.AzureSubscriptionOpt,
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		AzureSummaryMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)+".json"),
}

var AzureSummaryOutputProvders = []func(options []*types.Option) types.OutputProvider{
	op.NewConsoleProvider,
	op.NewJsonFileProvider,
	// op.NewMdTableProvider,
}

var AzureSummaryMetadata = modules.Metadata{
	Id:          "summary", // this will be the CLI command name
	Name:        "Summary",
	Description: "Summarize Azure resources",
	Platform:    modules.Azure,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAzureSummary(opts []*types.Option) (<-chan string, stages.Stage[string, []*ResourceCount], error) {
	pipeline, err := stages.ChainStages[string, []*ResourceCount](
		AzureSummaryStage,
	)

	subscription := types.GetOptionByName(options.AzureSubscriptionOpt.Name, opts).Value

	return stages.Generator([]string{subscription}), pipeline, err
}

func AzureSummaryStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []*ResourceCount {
	out := make(chan []*ResourceCount)
	go func() {
		defer close(out)
		var resourcesCount = []*ResourceCount{}
		for subscription := range in {

			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				log.Fatalf("failed to create credential: %v", err)
			}

			// Create a context
			ctx := context.Background()

			// Create a client
			client, err := armresources.NewClient(subscription, cred, nil)
			if err != nil {
				log.Fatalf("failed to create client: %v", err)
			}

			// List resources in the subscription
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					log.Fatalf("failed to get next page: %v", err)
				}

				for _, resource := range page.Value {
					resourcesCount = AddResourceCount(resourcesCount, *resource.Type)
				}
			}

			out <- resourcesCount

		}
	}()
	return out
}

type ResourceCount struct {
	ResourceType string
	Count        int
}

func AddResourceCount(resourcesCount []*ResourceCount, resourceType string) []*ResourceCount {
	for _, rc := range resourcesCount {
		if rc.ResourceType == resourceType {
			rc.Count++
			return resourcesCount
		}
	}

	// If no existing resource type match is found, add it to ResourcesCount with count 1
	resourcesCount = append(resourcesCount, &ResourceCount{
		ResourceType: resourceType,
		Count:        1,
	})
	return resourcesCount
}
