package reconaws

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/smithy-go/logging"

	"github.com/praetorian-inc/nebula/modules"
	. "github.com/praetorian-inc/nebula/modules/options"
	naws "github.com/praetorian-inc/nebula/pkg/nebula/aws/active_regions"
)

var logger = logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
	LOG_FILE := "nebula.log"

	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}

	f, err := os.OpenFile(LOG_FILE, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	handler := slog.NewJSONHandler(f, opts)
	logger := slog.New(handler)
	// TODO: The key for the request is `!BADKEY`, need to fix
	logger.Debug("Nebula", v...)

})

type AwsSummary struct {
	modules.BaseModule
}

var AwsSummaryRequiredOptions = []*Option{}

var AwsSummaryMetadata = modules.Metadata{
	Id:          "summary",
	Name:        "AWS Summary",
	Description: "Use cost explorer to summarize the services and regions in use.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewAwsSummary(options []*Option, run modules.Run) (modules.Module, error) {
	var m AwsSummary
	m.SetMetdata(AwsSummaryMetadata)
	m.Run = run
	m.Options = options

	return &m, nil
}

func (m *AwsSummary) Invoke() error {
	defer close(m.Run.Data)
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithClientLogMode(
			aws.LogRetries|
				aws.LogRequestWithBody|
				aws.LogRequestEventMessage|
				aws.LogResponseEventMessage),
		config.WithLogger(logger))

	if err != nil {
		fmt.Println("Failed to load AWS config:", err)
		return err
	}

	// Get all regions
	serviceRegions, err := naws.GetServiceAndRegions(cfg)
	if err != nil {
		fmt.Println("Failed to get regions:", err)
		return err
	}

	//fmt.Printf("Regions: %v\n", serviceRegions)

	// Iterate over each region
	for service, regions := range serviceRegions {
		fmt.Println("Service:", service)
		for _, region := range regions {
			fmt.Println("  Region:", region)
			if region == "NoRegion" {
				continue
			}
		}

		/*

			resTypeNames, found := helpers.ResolveCostExplorerService(service)
			if found {

				limit := 2
				var wg sync.WaitGroup
				wg.Add(limit)

				results := make(chan *cloudcontrol.ListResourcesOutput, limit)
				defer close(results)

				//p := pool.NewWithResults[[]*cloudcontrol.ListResourcesOutput]().WithMaxGoroutines(limit).WithErrors()

				for _, resType := range resTypeNames {
					resList, err := ListResources(cfg, resType)
					if err != nil {
						fmt.Println("Error listing resources:", err)
						continue
					}

					printCCResources(resList)
				}
			}
		*/

	}
	return nil
}

func ListResources(cfg aws.Config, rtype string) ([]*cloudcontrol.ListResourcesOutput, error) {
	fmt.Printf("%v\n", rtype)
	cc := cloudcontrol.NewFromConfig(cfg)
	params := &cloudcontrol.ListResourcesInput{}
	var results []*cloudcontrol.ListResourcesOutput

	params.TypeName = &rtype

	for {
		res, err := cc.ListResources(context.TODO(), params)

		if err != nil {
			fmt.Println("Error listing resources:", err)
			return nil, err
		}

		fmt.Printf("desc: %v\n", res.ResourceDescriptions)
		fmt.Printf("Next: %v\n", res.NextToken)
		results = append(results, res)

		if res.NextToken == nil {
			break
		}
	}

	return results, nil
}

func printCCResources(result []*cloudcontrol.ListResourcesOutput) {
	for _, resources := range result {
		fmt.Println(resources.TypeName)
		for _, resource := range resources.ResourceDescriptions {
			fmt.Println("Resource:", *resource.Identifier)
			fmt.Printf("  %v:\n", resource.Properties)
		}
	}
}
