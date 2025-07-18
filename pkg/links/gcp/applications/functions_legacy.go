package applications

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudfunctions/v1"
)

// FILE INFO:
// GcpFunctionInfoLink - get info of a single cloud function, Process(functionName string); needs project and region
// GcpFunctionListLink - list all cloud functions in a project, Process(resource tab.GCPResource)

type GcpFunctionInfoLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
	ProjectId        string
	Region           string
}

// creates a link to get info of a single cloud function
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
	gcpFunction, err := tab.NewGCPResource(
		function.Name,                     // resource name
		g.ProjectId,                       // accountRef (project ID)
		tab.GCPResourceFunction,           // resource type
		linkPostProcessFunction(function), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP function resource: %w", err)
	}
	gcpFunction.DisplayName = function.Name
	g.Send(gcpFunction)
	return nil
}

type GcpFunctionListLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
}

// creates a link to list all cloud functions in a project
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
	parent := fmt.Sprintf("projects/%s/locations/%s", resource.Name, "-")
	listReq := g.functionsService.Projects.Locations.Functions.List(parent)
	err := listReq.Pages(context.Background(), func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, function := range page.Functions {
			slog.Debug("Found function", "function", function.Name)
			gcpFunction, err := tab.NewGCPResource(
				function.Name,                     // resource name
				resource.Name,                     // accountRef (project ID)
				tab.GCPResourceFunction,           // resource type
				linkPostProcessFunction(function), // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP function resource", "error", err, "function", function.Name)
				continue
			}
			gcpFunction.DisplayName = function.Name
			g.Send(gcpFunction)
		}
		return nil
	})
	if err != nil {
		slog.Error("Failed to list functions in location", "error", err, "location", "-")
	}
	return nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessFunction(function *cloudfunctions.CloudFunction) map[string]any {
	properties := map[string]any{
		"name":                 function.Name,
		"description":          function.Description,
		"status":               function.Status,
		"version":              strconv.FormatInt(function.VersionId, 10),
		"entryPoint":           function.EntryPoint,
		"runtime":              function.Runtime,
		"serviceAccountEmail":  function.ServiceAccountEmail,
		"labels":               function.Labels,
		"environmentVariables": function.EnvironmentVariables,
		"maxInstances":         function.MaxInstances,
		"minInstances":         function.MinInstances,
		"vpcConnector":         function.VpcConnector,
		"ingressSettings":      function.IngressSettings,
	}
	if function.HttpsTrigger != nil && function.HttpsTrigger.Url != "" {
		properties["publicURL"] = function.HttpsTrigger.Url
	}
	return properties
}
