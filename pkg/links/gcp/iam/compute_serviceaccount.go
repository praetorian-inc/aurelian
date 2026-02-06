package iam

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/base"
	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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
	*base.NativeGCPLink
	computeService *compute.Service
}

// creates a link to extract service account information from compute instances
func NewGcpComputeServiceAccountLink(args map[string]any) *GcpComputeServiceAccountLink {
	link := &GcpComputeServiceAccountLink{
		NativeGCPLink: base.NewNativeGCPLink("gcp-compute-serviceaccount", args),
	}

	// Initialize compute service
	computeService, err := compute.NewService(context.Background(), link.ClientOptions()...)
	if err != nil {
		slog.Error("Failed to create compute service", "error", common.HandleGcpError(err, "failed to create compute service"))
	}
	link.computeService = computeService

	return link
}

func (g *GcpComputeServiceAccountLink) Parameters() []plugin.Parameter {
	return base.StandardGCPParams()
}

func (g *GcpComputeServiceAccountLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}

	slog.Debug("GcpComputeServiceAccountLink received resource", "type", resource.ResourceType, "name", resource.ResourceID)

	// Only process compute instance resources
	if resource.ResourceType != "compute_instance" {
		slog.Debug("Skipping non-instance resource", "type", resource.ResourceType, "name", resource.ResourceID)
		return nil, nil
	}

	// Extract instance details from properties
	data := resource.Properties
	if data == nil {
		slog.Debug("No data found for instance", "instance", resource.ResourceID)
		return nil, nil
	}

	instanceName, ok := data["name"].(string)
	if !ok {
		slog.Debug("Missing instance name in data", "resource", resource.ResourceID)
		return nil, nil
	}

	zone, ok := data["zone"].(string)
	if !ok {
		slog.Debug("Missing zone in data", "instance", instanceName)
		return nil, nil
	}

	// Extract project ID from the resource
	projectId := resource.AccountRef

	// Extract zone name from the full zone URL
	zoneName := extractZoneFromURL(zone)
	if zoneName == "" {
		slog.Debug("Could not extract zone name", "zone_url", zone)
		return nil, nil
	}

	slog.Debug("Processing compute instance for service account info",
		"instance", instanceName,
		"project", projectId,
		"zone", zoneName)

	// Get detailed instance information to extract service account data
	instance, err := g.computeService.Instances.Get(projectId, zoneName, instanceName).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, fmt.Sprintf("failed to get instance details for %s", instanceName))
	}

	results := make([]any, 0, len(instance.ServiceAccounts))

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
		saResource := &output.CloudResource{
			ResourceID:   fmt.Sprintf("%s/serviceaccounts/%s", projectId, serviceAccount.Email),
			DisplayName:  fmt.Sprintf("SA: %s (%s)", serviceAccount.Email, instanceName),
			ResourceType: "ComputeServiceAccount",
			Region:       resource.Region,
			Platform:     "gcp",
			AccountRef:   projectId,
			Properties: map[string]any{
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
		}

		slog.Debug("Extracted service account info",
			"instance", instanceName,
			"service_account", serviceAccount.Email,
			"is_default", saData.IsDefaultSA,
			"type", saData.ServiceAccountType)

		results = append(results, saResource)
	}

	return results, nil
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
