package iam

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
)

// FILE INFO:
// GcpComputeServiceAccountLink - Extract service account information from compute instances

// ComputeServiceAccountData represents service account data for a compute instance
type ComputeServiceAccountData struct {
	InstanceId          string   `json:"instance_id"`
	InstanceName        string   `json:"instance_name"`
	ProjectId           string   `json:"project_id"`
	Zone                string   `json:"zone"`
	ServiceAccountEmail string   `json:"service_account_email"`
	Scopes              []string `json:"scopes"`
	IsDefaultSA         bool     `json:"is_default_service_account"`
	ServiceAccountType  string   `json:"service_account_type"`
}

type GcpComputeServiceAccountLink struct {
	*base.GcpBaseLink
	computeService *compute.Service
}

// creates a link to extract service account information from compute instances
func NewGcpComputeServiceAccountLink(configs ...cfg.Config) chain.Link {
	g := &GcpComputeServiceAccountLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpComputeServiceAccountLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.computeService, err = compute.NewService(context.Background(), g.ClientOptions...)
	return common.HandleGcpError(err, "failed to create compute service")
}

func (g *GcpComputeServiceAccountLink) Process(resource tab.GCPResource) error {
	slog.Debug("GcpComputeServiceAccountLink received resource", "type", resource.ResourceType, "name", resource.Name)

	// Only process compute instance resources
	if resource.ResourceType != tab.GCPResourceInstance {
		slog.Debug("Skipping non-instance resource", "type", resource.ResourceType, "name", resource.Name)
		return nil
	}

	// Extract instance details from properties
	properties := resource.Properties
	if properties == nil {
		slog.Debug("No properties found for instance", "instance", resource.Name)
		return nil
	}

	instanceName, ok := properties["name"].(string)
	if !ok {
		slog.Debug("Missing instance name in properties", "resource", resource.Name)
		return nil
	}

	zone, ok := properties["zone"].(string)
	if !ok {
		slog.Debug("Missing zone in properties", "instance", instanceName)
		return nil
	}

	// Extract project ID from the resource
	projectId := resource.AccountRef

	// Extract zone name from the full zone URL
	zoneName := extractZoneFromURL(zone)
	if zoneName == "" {
		slog.Debug("Could not extract zone name", "zone_url", zone)
		return nil
	}

	slog.Debug("Processing compute instance for service account info",
		"instance", instanceName,
		"project", projectId,
		"zone", zoneName)

	// Get detailed instance information to extract service account data
	instance, err := g.computeService.Instances.Get(projectId, zoneName, instanceName).Do()
	if err != nil {
		return common.HandleGcpError(err, fmt.Sprintf("failed to get instance details for %s", instanceName))
	}

	// Process service accounts attached to the instance
	for _, serviceAccount := range instance.ServiceAccounts {
		saData := ComputeServiceAccountData{
			InstanceId:          strconv.FormatUint(instance.Id, 10),
			InstanceName:        instanceName,
			ProjectId:           projectId,
			Zone:                zoneName,
			ServiceAccountEmail: serviceAccount.Email,
			Scopes:              serviceAccount.Scopes,
			IsDefaultSA:         isDefaultServiceAccount(serviceAccount.Email),
			ServiceAccountType:  categorizeServiceAccount(serviceAccount.Email),
		}

		// Create a new resource for the service account data
		saResource, err := tab.NewGCPResource(
			fmt.Sprintf("%d-sa-%s", instance.Id, sanitizeEmail(serviceAccount.Email)),
			resource.AccountRef,
			tab.CloudResourceType("ComputeServiceAccount"),
			map[string]any{
				"instance_id":           saData.InstanceId,
				"instance_name":         saData.InstanceName,
				"project_id":            saData.ProjectId,
				"zone":                  saData.Zone,
				"service_account_email": saData.ServiceAccountEmail,
				"scopes":                saData.Scopes,
				"is_default_sa":         saData.IsDefaultSA,
				"service_account_type":  saData.ServiceAccountType,
				"sa_data":               saData,
			},
		)
		if err != nil {
			slog.Error("Failed to create service account resource", "error", err, "instance", instanceName)
			continue
		}

		saResource.DisplayName = fmt.Sprintf("SA: %s (%s)", serviceAccount.Email, instanceName)
		saResource.Region = resource.Region

		slog.Debug("Extracted service account info",
			"instance", instanceName,
			"service_account", serviceAccount.Email,
			"is_default", saData.IsDefaultSA,
			"type", saData.ServiceAccountType)

		g.Send(saResource)
	}

	return nil
}

// Helper function to extract zone name from full zone URL
func extractZoneFromURL(zoneURL string) string {
	// Zone URL format: https://www.googleapis.com/compute/v1/projects/PROJECT_ID/zones/ZONE_NAME
	parts := strings.Split(zoneURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// Helper function to identify default service accounts
func isDefaultServiceAccount(email string) bool {
	// Default compute service account pattern: PROJECT_NUMBER-compute@developer.gserviceaccount.com
	// Default App Engine service account pattern: PROJECT_ID@appspot.gserviceaccount.com
	return strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") ||
		strings.HasSuffix(email, "@appspot.gserviceaccount.com")
}

// Helper function to categorize service account types
func categorizeServiceAccount(email string) string {
	if strings.HasSuffix(email, "-compute@developer.gserviceaccount.com") {
		return "default-compute"
	}
	if strings.HasSuffix(email, "@appspot.gserviceaccount.com") {
		return "default-appengine"
	}
	if strings.HasSuffix(email, ".gserviceaccount.com") {
		return "user-managed"
	}
	return "unknown"
}

// Helper function to sanitize email for resource naming
func sanitizeEmail(email string) string {
	sanitized := strings.ReplaceAll(email, "@", "-at-")
	sanitized = strings.ReplaceAll(sanitized, ".", "-")
	return sanitized
}
