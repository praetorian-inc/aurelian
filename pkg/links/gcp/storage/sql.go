package storage

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/sqladmin/v1"
)

// FILE INFO:
// GcpSQLInstanceInfoLink - get info of a single SQL instance, Process(instanceName string); needs project
// GcpSQLInstanceListLink - list all SQL instances in a project, Process(resource *output.CloudResource); needs project

const (
	gcpSQLInstanceInfoName = "gcp-sql-instance-info"
	gcpSQLInstanceListName = "gcp-sql-instance-list"
)

type GcpSQLInstanceInfoLink struct {
	*base.NativeGCPLink
	sqlService *sqladmin.Service
	ProjectId  string
}

// creates a link to get info of a single SQL instance
func NewGcpSQLInstanceInfoLink(args map[string]any) plugin.Link {
	return &GcpSQLInstanceInfoLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpSQLInstanceInfoName, args),
	}
}

func (g *GcpSQLInstanceInfoLink) Parameters() []plugin.Parameter {
	params := append(base.StandardGCPParams(),
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
	)
	return params
}

func (g *GcpSQLInstanceInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	instanceName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	// Lazy initialization
	if g.sqlService == nil {
		var err error
		g.sqlService, err = sqladmin.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create SQL admin service: %w", err)
		}
		if projectVal, ok := g.Args()["project"].(string); ok {
			g.ProjectId = projectVal
		}
	}

	instance, err := g.sqlService.Instances.Get(g.ProjectId, instanceName).Context(ctx).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get SQL instance")
	}
	gcpSQLInstance := &output.CloudResource{
		Platform:     "gcp",
		ResourceID:   fmt.Sprintf("projects/%s/instances/%s", g.ProjectId, instance.Name),
		AccountRef:   g.ProjectId,
		ResourceType: "sqladmin.googleapis.com/Instance",
		DisplayName:  instance.Name,
		Region:       instance.Region,
		Properties:   linkPostProcessSQLInstance(instance),
	}
	return []any{gcpSQLInstance}, nil
}

type GcpSQLInstanceListLink struct {
	*base.NativeGCPLink
	sqlService *sqladmin.Service
}

// creates a link to list all SQL instances in a project
func NewGcpSQLInstanceListLink(args map[string]any) plugin.Link {
	return &GcpSQLInstanceListLink{
		NativeGCPLink: base.NewNativeGCPLink(gcpSQLInstanceListName, args),
	}
}

func (g *GcpSQLInstanceListLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpSQLInstanceListLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource input, got %T", input)
	}
	if resource.ResourceType != "cloudresourcemanager.googleapis.com/Project" {
		return nil, nil
	}

	// Lazy initialization
	if g.sqlService == nil {
		var err error
		g.sqlService, err = sqladmin.NewService(ctx, g.ClientOptions()...)
		if err != nil {
			return nil, fmt.Errorf("failed to create SQL admin service: %w", err)
		}
	}

	projectId := resource.ResourceID
	listCall := g.sqlService.Instances.List(projectId)
	resp, err := listCall.Context(ctx).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list SQL instances in project")
	}

	var results []any
	for _, instance := range resp.Items {
		gcpSQLInstance := &output.CloudResource{
			Platform:     "gcp",
			ResourceID:   fmt.Sprintf("projects/%s/instances/%s", projectId, instance.Name),
			AccountRef:   projectId,
			ResourceType: "sqladmin.googleapis.com/Instance",
			DisplayName:  instance.Name,
			Region:       instance.Region,
			Properties:   linkPostProcessSQLInstance(instance),
		}
		results = append(results, gcpSQLInstance)
	}
	return results, nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessSQLInstance(instance *sqladmin.DatabaseInstance) map[string]any {
	properties := map[string]any{
		"name":            instance.Name,
		"project":         instance.Project,
		"databaseVersion": instance.DatabaseVersion,
		"region":          instance.Region,
		"state":           instance.State,
		"backendType":     instance.BackendType,
		"instanceType":    instance.InstanceType,
		"connectionName":  instance.ConnectionName,
		"selfLink":        instance.SelfLink,
	}
	// minor information for now, additional info can be added later
	if instance.Settings != nil {
		if instance.Settings.IpConfiguration != nil {
			properties["ipv4Enabled"] = fmt.Sprintf("%v", instance.Settings.IpConfiguration.Ipv4Enabled)
			properties["requireSsl"] = fmt.Sprintf("%v", instance.Settings.IpConfiguration.RequireSsl)
			if instance.Settings.IpConfiguration.PrivateNetwork != "" {
				properties["privateNetwork"] = instance.Settings.IpConfiguration.PrivateNetwork
			}
		}
	}
	if len(instance.IpAddresses) > 0 {
		var publicIPs, privateIPs string
		for i, ip := range instance.IpAddresses {
			if ip.Type == "PRIMARY" {
				if publicIPs != "" {
					publicIPs += ","
				}
				publicIPs += ip.IpAddress
			} else if ip.Type == "PRIVATE" {
				if i > 0 {
					privateIPs += ","
				}
				privateIPs += ip.IpAddress
			}
		}
		if publicIPs != "" {
			properties["publicIPs"] = publicIPs
		}
		if privateIPs != "" {
			properties["privateIPs"] = privateIPs
		}
	}
	return properties
}

// Note: init() registration removed - native plugins register via Parameters() method
