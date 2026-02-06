package compute

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// FILE INFO:
// GcpInstanceInfoLink - get info of a single compute instance, Process(instanceName string); needs project and zone
// GcpInstanceListLink - list all compute instances in a project, Process(resource tab.GCPResource)
// GcpInstanceSecretsLink - extract secrets from a compute instance, Process(input tab.GCPResource)

type GcpInstanceInfoLink struct {
	*plugin.BaseLink
	computeService *compute.Service
	ProjectId      string
	Zone           string
	ClientOptions  []option.ClientOption
}

// creates a link to get info of a single compute instance
func NewGcpInstanceInfoLink(args map[string]any) *GcpInstanceInfoLink {
	return &GcpInstanceInfoLink{
		BaseLink: plugin.NewBaseLink("gcp-instance-info", args),
	}
}

func (g *GcpInstanceInfoLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("zone", "GCP zone", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpInstanceInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}

		projectId := g.ArgString("project", "")
		if projectId == "" {
			return nil, fmt.Errorf("project parameter is required")
		}
		g.ProjectId = projectId

		zone := g.ArgString("zone", "")
		if zone == "" {
			return nil, fmt.Errorf("zone parameter is required")
		}
		g.Zone = zone
	}

	instanceName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input (instance name), got %T", input)
	}

	instance, err := g.computeService.Instances.Get(g.ProjectId, g.Zone, instanceName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance %s: %w", instanceName, err)
	}

	gcpInstance, err := tab.NewGCPResource(
		strconv.FormatUint(instance.Id, 10),      // resource name
		g.ProjectId,                              // accountRef (project ID)
		tab.GCPResourceInstance,                  // resource type
		linkPostProcessComputeInstance(instance), // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP instance resource: %w", err)
	}
	gcpInstance.DisplayName = instance.Name

	return []any{gcpInstance}, nil
}

type GcpInstanceListLink struct {
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to list all compute instances in a project
func NewGcpInstanceListLink(args map[string]any) *GcpInstanceListLink {
	return &GcpInstanceListLink{
		BaseLink: plugin.NewBaseLink("gcp-instance-list", args),
	}
}

func (g *GcpInstanceListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpInstanceListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, common.HandleGcpError(err, "failed to create compute service")
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}

	projectId := resource.Name
	zonesListCall := g.computeService.Zones.List(projectId)
	zonesResp, err := zonesListCall.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list zones in project")
	}

	var outputs []any
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, zone := range zonesResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(zoneName string) {
			defer wg.Done()
			defer func() { <-sem }()

			listReq := g.computeService.Instances.List(projectId, zoneName)
			err := listReq.Pages(ctx, func(page *compute.InstanceList) error {
				for _, instance := range page.Items {
					gcpInstance, err := tab.NewGCPResource(
						strconv.FormatUint(instance.Id, 10),      // resource name
						projectId,                                // accountRef (project ID)
						tab.GCPResourceInstance,                  // resource type
						linkPostProcessComputeInstance(instance), // properties
					)
					if err != nil {
						slog.Error("Failed to create GCP instance resource", "error", err, "instance", instance.Name)
						continue
					}
					gcpInstance.DisplayName = instance.Name
					slog.Debug("Sending GCP instance", "instance", gcpInstance.DisplayName)

					mu.Lock()
					outputs = append(outputs, gcpInstance)
					mu.Unlock()
				}
				return nil
			})
			if handledErr := common.HandleGcpError(err, "failed to list instances in zone"); handledErr != nil {
				slog.Error("error", "error", handledErr, "zone", zoneName)
			}
		}(zone.Name)
	}
	wg.Wait()

	return outputs, nil
}

type GcpInstanceSecretsLink struct {
	*plugin.BaseLink
	computeService *compute.Service
	ClientOptions  []option.ClientOption
}

// creates a link to scan compute instance for secrets
func NewGcpInstanceSecretsLink(args map[string]any) *GcpInstanceSecretsLink {
	return &GcpInstanceSecretsLink{
		BaseLink: plugin.NewBaseLink("gcp-instance-secrets", args),
	}
}

func (g *GcpInstanceSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpInstanceSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.computeService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.computeService, err = compute.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create compute service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceInstance {
		return nil, nil
	}

	projectId := resource.AccountRef
	instanceName := resource.DisplayName
	zoneURL, _ := resource.Properties["zone"].(string)
	zone := path.Base(zoneURL)

	if projectId == "" || zone == "" || instanceName == "" {
		return nil, nil
	}

	inst, err := g.computeService.Instances.Get(projectId, zone, instanceName).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get instance for secrets extraction")
	}

	var metadataContent strings.Builder
	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			if item == nil || item.Value == nil || *item.Value == "" {
				continue
			}
			metadataContent.WriteString(fmt.Sprintf("GCP Instance Metadata: %s\n", item.Key))
			metadataContent.WriteString(*item.Value)
			metadataContent.WriteString("\n\n")
		}
	}

	var outputs []any
	if metadataContent.Len() > 0 {
		outputs = append(outputs, types.NpInput{
			Content: metadataContent.String(),
			Provenance: types.NpProvenance{
				Platform:     "gcp",
				ResourceType: fmt.Sprintf("%s::Metadata", tab.GCPResourceInstance.String()),
				ResourceID:   resource.Name,
				Region:       zone,
				AccountID:    projectId,
			},
		})
	}

	return outputs, nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessComputeInstance(instance *compute.Instance) map[string]any {
	properties := map[string]any{
		"name":        instance.Name,
		"id":          instance.Id,
		"description": instance.Description,
		"status":      instance.Status,
		"zone":        instance.Zone,
		"labels":      instance.Labels,
		"selfLink":    instance.SelfLink,
	}
	for _, networkInterface := range instance.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if accessConfig.NatIP != "" {
				if utils.IsIPv4(accessConfig.NatIP) {
					properties["publicIP"] = accessConfig.NatIP
				}
			}
			if accessConfig.PublicPtrDomainName != "" {
				properties["publicDomain"] = accessConfig.PublicPtrDomainName
			}
		}
		for _, ipv6AccessConfig := range networkInterface.Ipv6AccessConfigs {
			if ipv6AccessConfig.ExternalIpv6 != "" {
				if utils.IsIPv6(ipv6AccessConfig.ExternalIpv6) {
					properties["publicIPv6"] = ipv6AccessConfig.ExternalIpv6
				}
			}
		}
	}
	return properties
}
