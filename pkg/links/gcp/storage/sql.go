package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/sqladmin/v1"
)

// FILE INFO:
// GcpSQLInstanceInfoLink - get info of a single SQL instance, Process(instanceName string); needs project
// GcpSQLInstanceListLink - list all SQL instances in a project, Process(resource tab.GCPResource); needs project

type GcpSQLInstanceInfoLink struct {
	*base.GcpBaseLink
	sqlService *sqladmin.Service
	ProjectId  string
}

// creates a link to get info of a single SQL instance
func NewGcpSQLInstanceInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpSQLInstanceInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpSQLInstanceInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
	)
	return params
}

func (g *GcpSQLInstanceInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.sqlService, err = sqladmin.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create SQL admin service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	return nil
}

func (g *GcpSQLInstanceInfoLink) Process(instanceName string) error {
	instance, err := g.sqlService.Instances.Get(g.ProjectId, instanceName).Do()
	if err != nil {
		return fmt.Errorf("failed to get SQL instance %s: %w", instanceName, err)
	}
	gcpSQLInstance, err := tab.NewGCPResource(
		instance.Name,                        // resource name (instance name)
		g.ProjectId,                          // accountRef (project ID)
		tab.GCPResourceSQLInstance,           // resource type
		linkPostProcessSQLInstance(instance), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP SQL instance resource: %w", err)
	}
	g.Send(gcpSQLInstance)
	return nil
}

type GcpSQLInstanceListLink struct {
	*base.GcpBaseLink
	sqlService *sqladmin.Service
}

// creates a link to list all SQL instances in a project
func NewGcpSQLInstanceListLink(configs ...cfg.Config) chain.Link {
	g := &GcpSQLInstanceListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpSQLInstanceListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.sqlService, err = sqladmin.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create SQL admin service: %w", err)
	}
	return nil
}

func (g *GcpSQLInstanceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	listCall := g.sqlService.Instances.List(projectId)
	resp, err := listCall.Do()
	if err != nil {
		return fmt.Errorf("failed to list SQL instances in project %s: %w", projectId, err)
	}
	for _, instance := range resp.Items {
		gcpSQLInstance, err := tab.NewGCPResource(
			instance.Name,                        // resource name
			projectId,                            // accountRef (project ID)
			tab.GCPResourceSQLInstance,           // resource type
			linkPostProcessSQLInstance(instance), // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP SQL instance resource", "error", err, "instance", instance.Name)
			continue
		}
		g.Send(gcpSQLInstance)
	}
	return nil
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
	// minior information for now, additional info can be added later
	if instance.Settings != nil {
		if instance.Settings.IpConfiguration != nil {
			ipConfig := map[string]any{
				"ipv4Enabled":    instance.Settings.IpConfiguration.Ipv4Enabled,
				"requireSsl":     instance.Settings.IpConfiguration.RequireSsl,
				"privateNetwork": instance.Settings.IpConfiguration.PrivateNetwork,
			}
			properties["ipConfig"] = ipConfig
		}
	}
	if len(instance.IpAddresses) > 0 {
		var publicIPs []string
		var privateIPs []string
		for _, ip := range instance.IpAddresses {
			if ip.Type == "PRIMARY" {
				publicIPs = append(publicIPs, ip.IpAddress)
			} else if ip.Type == "PRIVATE" {
				privateIPs = append(privateIPs, ip.IpAddress)
			}
		}
		if len(publicIPs) > 0 {
			properties["publicIPs"] = publicIPs
		}
		if len(privateIPs) > 0 {
			properties["privateIPs"] = privateIPs
		}
	}
	return properties
}
