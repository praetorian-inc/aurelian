package storage

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
	"google.golang.org/api/sqladmin/v1"
)

// FILE INFO:
// GcpSQLInstanceInfoLink
// GcpSQLInstanceListLink

// get information about a SQL instance
type GcpSQLInstanceInfoLink struct {
	*base.GcpBaseLink
	sqlService *sqladmin.Service
	ProjectId  string
}

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
	properties := linkPostProcessSQLInstance(instance, true)
	gcpSQLInstance, err := tab.NewGCPResource(
		instance.Name,              // resource name
		g.ProjectId,                // accountRef (project ID)
		tab.GCPResourceSQLInstance, // resource type
		properties,                 // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP SQL instance resource: %w", err)
	}
	g.Send(gcpSQLInstance)
	return nil
}

// linkPostProcessSQLInstance consolidates SQL instance processing logic for both info and list links
// detailedInfo controls whether to include detailed settings and metadata
func linkPostProcessSQLInstance(instance *sqladmin.DatabaseInstance, detailedInfo bool) map[string]any {
	properties := map[string]any{
		"name":            instance.Name,
		"project":         instance.Project,
		"databaseVersion": instance.DatabaseVersion,
		"region":          instance.Region,
		"state":           instance.State,
		"backendType":     instance.BackendType,
		"instanceType":    instance.InstanceType,
		"connectionName":  instance.ConnectionName,
		"createdTime":     instance.CreateTime,
		"selfLink":        instance.SelfLink,
	}

	// Include detailed metadata only for info links
	if detailedInfo {
		properties["currentDiskSize"] = instance.CurrentDiskSize
		properties["maxDiskSize"] = instance.MaxDiskSize
		properties["serviceAccountEmailAddress"] = instance.ServiceAccountEmailAddress
	}

	// Process settings information
	if instance.Settings != nil {
		if detailedInfo {
			// Detailed settings as nested object for info links
			settings := map[string]any{
				"tier":                   instance.Settings.Tier,
				"availabilityType":       instance.Settings.AvailabilityType,
				"pricingPlan":            instance.Settings.PricingPlan,
				"activationPolicy":       instance.Settings.ActivationPolicy,
				"storageAutoResize":      instance.Settings.StorageAutoResize,
				"storageAutoResizeLimit": instance.Settings.StorageAutoResizeLimit,
				"dataDiskSizeGb":         instance.Settings.DataDiskSizeGb,
				"dataDiskType":           instance.Settings.DataDiskType,
			}
			properties["settings"] = settings
		} else {
			// Flattened basic settings for list links
			properties["tier"] = instance.Settings.Tier
			properties["availabilityType"] = instance.Settings.AvailabilityType
			properties["pricingPlan"] = instance.Settings.PricingPlan
		}

		// Check for public IP (common logic)
		if instance.Settings.IpConfiguration != nil {
			ipConfig := instance.Settings.IpConfiguration
			properties["ipv4Enabled"] = ipConfig.Ipv4Enabled
			properties["requireSsl"] = ipConfig.RequireSsl

			if ipConfig.Ipv4Enabled {
				properties["hasPublicIP"] = true
			}
		}
	}

	// Add IP addresses (common logic, but different handling)
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

// list SQL instances within a project
type GcpSQLInstanceListLink struct {
	*base.GcpBaseLink
	sqlService *sqladmin.Service
}

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

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, instance := range resp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(inst *sqladmin.DatabaseInstance) {
			defer wg.Done()
			defer func() { <-sem }()

			properties := linkPostProcessSQLInstance(inst, false)
			gcpSQLInstance, err := tab.NewGCPResource(
				inst.Name,                  // resource name
				projectId,                  // accountRef (project ID)
				tab.GCPResourceSQLInstance, // resource type
				properties,                 // properties
			)
			if err != nil {
				slog.Error("Failed to create GCP SQL instance resource", "error", err, "instance", inst.Name)
				return
			}
			g.Send(gcpSQLInstance)
		}(instance)
	}
	wg.Wait()
	return nil
}
