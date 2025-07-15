package compute

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudfunctions/v1"
)

// FILE INFO:
// GcpFunctionInfoLink
// GcpFunctionListLink

// get information about a cloud function
type GcpFunctionInfoLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
	ProjectId        string
	Region           string
}

func NewGcpFunctionInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpFunctionInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFunctionInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		options.GcpRegion(),
	)
	return params
}

func (g *GcpFunctionInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.functionsService, err = cloudfunctions.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud functions service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	region, err := cfg.As[string](g.Arg("region"))
	if err != nil {
		return fmt.Errorf("failed to get region: %w", err)
	}
	g.Region = region
	return nil
}

func (g *GcpFunctionInfoLink) Process(functionName string) error {
	functionPath := fmt.Sprintf("projects/%s/locations/%s/functions/%s", g.ProjectId, g.Region, functionName)
	function, err := g.functionsService.Projects.Locations.Functions.Get(functionPath).Do()
	if err != nil {
		return fmt.Errorf("failed to get function %s: %w", functionName, err)
	}
	properties := map[string]any{
		"name":                 function.Name,
		"description":          function.Description,
		"status":               function.Status,
		"entryPoint":           function.EntryPoint,
		"runtime":              function.Runtime,
		"timeout":              function.Timeout,
		"availableMemoryMb":    function.AvailableMemoryMb,
		"serviceAccountEmail":  function.ServiceAccountEmail,
		"updateTime":           function.UpdateTime,
		"versionId":            function.VersionId,
		"labels":               function.Labels,
		"environmentVariables": function.EnvironmentVariables,
		"sourceArchiveUrl":     function.SourceArchiveUrl,
		"sourceRepository":     function.SourceRepository,
		"httpsTrigger":         function.HttpsTrigger,
		"eventTrigger":         function.EventTrigger,
		"maxInstances":         function.MaxInstances,
		"minInstances":         function.MinInstances,
		"vpcConnector":         function.VpcConnector,
		"ingressSettings":      function.IngressSettings,
	}
	gcpFunction, err := tab.NewGCPResource(
		function.Name,           // resource name
		g.ProjectId,             // accountRef (project ID)
		tab.GCPResourceFunction, // resource type
		properties,              // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP function resource: %w", err)
	}
	g.Send(gcpFunction)
	return nil
}

// list functions within a project
type GcpFunctionListLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
}

func NewGcpFunctionListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFunctionListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFunctionListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.functionsService, err = cloudfunctions.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud functions service: %w", err)
	}
	return nil
}

func (g *GcpFunctionListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	regionsListCall := g.functionsService.Projects.Locations.List(fmt.Sprintf("projects/%s", projectId))
	regionsResp, err := regionsListCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list regions in project %s: %w", projectId, err)
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, location := range regionsResp.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationId string) {
			defer wg.Done()
			defer func() { <-sem }()
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, locationId)
			listReq := g.functionsService.Projects.Locations.Functions.List(parent)
			err := listReq.Pages(context.Background(), func(page *cloudfunctions.ListFunctionsResponse) error {
				for _, function := range page.Functions {
					properties := map[string]any{
						"name":                 function.Name,
						"description":          function.Description,
						"status":               function.Status,
						"entryPoint":           function.EntryPoint,
						"runtime":              function.Runtime,
						"timeout":              function.Timeout,
						"availableMemoryMb":    function.AvailableMemoryMb,
						"serviceAccountEmail":  function.ServiceAccountEmail,
						"updateTime":           function.UpdateTime,
						"versionId":            function.VersionId,
						"labels":               function.Labels,
						"environmentVariables": function.EnvironmentVariables,
						"sourceArchiveUrl":     function.SourceArchiveUrl,
						"sourceRepository":     function.SourceRepository,
						"httpsTrigger":         function.HttpsTrigger,
						"eventTrigger":         function.EventTrigger,
						"maxInstances":         function.MaxInstances,
						"minInstances":         function.MinInstances,
						"vpcConnector":         function.VpcConnector,
						"ingressSettings":      function.IngressSettings,
					}
					gcpFunction, err := tab.NewGCPResource(
						function.Name,           // resource name
						projectId,               // accountRef (project ID)
						tab.GCPResourceFunction, // resource type
						properties,              // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP function resource", "error", err, "function", function.Name)
						continue
					}
					g.Send(gcpFunction)
				}
				return nil
			})
			if err != nil {
				slog.Error("Failed to list functions in location", "error", err, "location", locationId)
			}
		}(location.LocationId)
	}
	wg.Wait()
	return nil
}
