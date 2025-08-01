package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/organization"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var opts = []*types.Option{&options.LogLevelOpt}

// Common Azure locations
var AzureLocations = []string{
	"eastus", "eastus2", "westus", "westus2", "centralus",
	"northeurope", "westeurope", "southeastasia", "eastasia",
	"japaneast", "japanwest", "australiaeast", "australiasoutheast",
	"southcentralus", "northcentralus", "brazilsouth",
	"centralindia", "southindia", "westindia",
}

// ClientSet holds common Azure clients
type ClientSet struct {
	Cred                 *azidentity.DefaultAzureCredential
	RoleDefClient        *armauthorization.RoleDefinitionsClient
	AuthClient           *armauthorization.RoleAssignmentsClient
	ResourceClient       *armresources.Client
	ResourceGroupsClient *armresources.ResourceGroupsClient
	SubscriptionClient   *armsubscriptions.Client
	GraphClient          *msgraphsdk.GraphServiceClient
}

// WorkerConfig defines worker pool configuration
type WorkerConfig struct {
	MaxWorkers     int
	BatchSize      int
	RequestsPerSec int
	TimeoutSeconds int
}

// DefaultWorkerConfig returns standard worker pool settings
func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		MaxWorkers:     25,
		BatchSize:      50,
		RequestsPerSec: 20,
		TimeoutSeconds: 45,
	}
}

// ResourceCount holds the count for each Azure resource type
type ResourceCount struct {
	ResourceType string
	Count        int
}

// AzureEnvironmentDetails holds all Azure environment information
type AzureEnvironmentDetails struct {
	TenantName       string
	TenantID         string
	SubscriptionID   string
	SubscriptionName string
	State            string
	Tags             map[string]*string
	Resources        []*ResourceCount
}

// ScanConfig holds the configuration for a resource type scan
type ScanConfig struct {
	Subscriptions []string
	ResourceTypes []string
}

// GetEnvironmentDetails gets all Azure environment details
func GetEnvironmentDetails(ctx context.Context, subscriptionID string, opts []*types.Option) (*AzureEnvironmentDetails, error) {
	// Get credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}

	// Get subscription details
	sub, err := GetSubscriptionDetails(ctx, cred, subscriptionID)
	if err != nil {
		return nil, err
	}

	// Get tenant details
	tenantName, tenantID, err := GetTenantDetails(ctx, cred)
	if err != nil {
		return nil, err
	}

	// Get resource counts
	resourceClient, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	resources, err := CountResources(ctx, resourceClient)
	if err != nil {
		return nil, err
	}

	// Convert State to string, handling the pointer
	var stateStr string
	if sub.State != nil {
		stateStr = string(*sub.State)
	} else {
		stateStr = "Unknown"
	}

	return &AzureEnvironmentDetails{
		TenantName:       tenantName,
		TenantID:         tenantID,
		SubscriptionID:   *sub.SubscriptionID,
		SubscriptionName: *sub.DisplayName,
		State:            stateStr,
		Tags:             sub.Tags,
		Resources:        resources,
	}, nil
}

// GetTenantDetails gets details about the Azure tenant
func GetTenantDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential) (string, string, error) {
	// Initialize clients or reuse existing credentials
	clients, err := InitializeClients("", cred)
	if err != nil {
		return "", "", fmt.Errorf("failed to initialize clients: %v", err)
	}

	org, err := clients.GraphClient.Organization().Get(ctx, &organization.OrganizationRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return "", "", fmt.Errorf("failed to get organization details: %v", err)
	}

	tenantName := "Unknown"
	tenantID := "Unknown"

	if orgValue := org.GetValue(); orgValue != nil && len(orgValue) > 0 {
		if displayName := orgValue[0].GetDisplayName(); displayName != nil {
			tenantName = *displayName
		}
		if id := orgValue[0].GetId(); id != nil {
			tenantID = *id
		}
	}

	return tenantName, tenantID, nil
}

// CountResources counts Azure resources by type
func CountResources(ctx context.Context, client *armresources.Client) ([]*ResourceCount, error) {
	var resourcesCount []*ResourceCount
	pager := client.NewListPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of resources: %v", err)
		}

		for _, resource := range page.Value {
			resourcesCount = addResourceCount(resourcesCount, *resource.Type)
		}
	}

	return resourcesCount, nil
}

// addResourceCount adds or updates a resource count
func addResourceCount(resourcesCount []*ResourceCount, resourceType string) []*ResourceCount {
	for _, rc := range resourcesCount {
		if rc.ResourceType == resourceType {
			rc.Count++
			return resourcesCount
		}
	}

	resourcesCount = append(resourcesCount, &ResourceCount{
		ResourceType: resourceType,
		Count:        1,
	})
	return resourcesCount
}

// InitializeClients creates a new set of commonly used Azure clients
func InitializeClients(subscriptionID string, cred *azidentity.DefaultAzureCredential) (*ClientSet, error) {
	if cred == nil {
		var err error
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
		}
	}

	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %v", err)
	}

	authClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, &arm.ClientOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %v", err)
	}

	resourceClient, err := armresources.NewClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource client: %v", err)
	}

	resourceGroupsClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource groups client: %v", err)
	}

	subscriptionClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription client: %v", err)
	}

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create graph client: %v", err)
	}

	return &ClientSet{
		Cred:                 cred,
		RoleDefClient:        roleDefClient,
		AuthClient:           authClient,
		ResourceClient:       resourceClient,
		ResourceGroupsClient: resourceGroupsClient,
		SubscriptionClient:   subscriptionClient,
		GraphClient:          graphClient,
	}, nil
}

// WorkerPool manages a pool of workers for processing Azure resources
type WorkerPool[T any, R any] struct {
	Config      WorkerConfig
	ProcessFunc func(context.Context, *ClientSet, T) ([]R, error)
	Clients     *ClientSet
	RoleCache   *sync.Map
}

// NewWorkerPool creates a new worker pool with the given configuration
func NewWorkerPool[T any, R any](config WorkerConfig, clients *ClientSet, processFunc func(context.Context, *ClientSet, T) ([]R, error)) *WorkerPool[T, R] {
	return &WorkerPool[T, R]{
		Config:      config,
		ProcessFunc: processFunc,
		Clients:     clients,
		RoleCache:   &sync.Map{},
	}
}

// Process runs the worker pool on the given input channel
func (wp *WorkerPool[T, R]) Process(ctx context.Context, input <-chan T) ([]R, error) {
	logger := logs.NewStageLogger(ctx, []*types.Option{}, "WorkerPool")

	var (
		results = make([]R, 0)
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Create rate limiter
	rateLimiter := time.NewTicker(time.Second / time.Duration(wp.Config.RequestsPerSec))
	defer rateLimiter.Stop()

	// Start workers
	errChan := make(chan error, wp.Config.MaxWorkers)
	for i := 0; i < wp.Config.MaxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for item := range input {
				<-rateLimiter.C // Rate limiting

				// Process with timeout
				itemCtx, cancel := context.WithTimeout(ctx, time.Duration(wp.Config.TimeoutSeconds)*time.Second)
				itemResults, err := wp.ProcessFunc(itemCtx, wp.Clients, item)
				cancel()

				if err != nil {
					if strings.Contains(strings.ToLower(err.Error()), "throttl") {
						time.Sleep(time.Duration(workerID+1) * 500 * time.Millisecond)
						continue
					}
					logger.Error("worker failed", slog.Int("worker", workerID), slog.String("error", err.Error()))
					continue
				}

				if len(itemResults) > 0 {
					mu.Lock()
					results = append(results, itemResults...)
					mu.Unlock()
					logger.Debug(fmt.Sprintf("Worker %d processed %d results", workerID, len(itemResults)))
				}
			}
		}(i)
	}

	// Wait for completion
	wg.Wait()
	close(errChan)

	// Check for errors
	select {
	case err := <-errChan:
		if err != nil {
			return nil, err
		}
	default:
	}

	return results, nil
}

// ProcessWithLogging wraps Process with standard logging
func (wp *WorkerPool[T, R]) ProcessWithLogging(ctx context.Context, input <-chan T, description string) ([]R, error) {
	logger := logs.NewStageLogger(ctx, opts, "WorkerPool")
	message.Info("Starting to process %s...", description)

	results, err := wp.Process(ctx, input)
	if err != nil {
		logger.Error("Error processing %s: %v", description, err)
		return nil, err
	}

	logger.Info("Completed processing %s. Found %d results", description, len(results))
	return results, nil
}

// RoleAssignmentProcessor handles common role assignment processing
type RoleAssignmentProcessor struct {
	cache *sync.Map
}

func NewRoleAssignmentProcessor() *RoleAssignmentProcessor {
	return &RoleAssignmentProcessor{
		cache: &sync.Map{},
	}
}

// ProcessRoleAssignments retrieves role assignments for a given scope
func (p *RoleAssignmentProcessor) ProcessRoleAssignments(
	ctx context.Context,
	clients *ClientSet,
	scope string,
	scopeType string,
	scopeDisplayName string,
	subscriptionID string,
	subscriptionName string,
) ([]*types.RoleAssignmentDetails, error) {
	var assignments []*types.RoleAssignmentDetails

	slog.Debug(fmt.Sprintf("Processing role assignments for %s: %s", scopeType, scopeDisplayName))
	assignmentPager := clients.AuthClient.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})

	assignmentCount := 0
	for assignmentPager.More() {
		page, err := assignmentPager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting role assignments: %v", err)
		}

		for _, assignment := range page.Value {
			if assignment == nil || assignment.Properties == nil {
				slog.Debug("Skipping nil assignment or properties")
				continue
			}

			assignmentCount++

			// Get role name from cache or API
			roleName := ""
			if assignment.Properties.RoleDefinitionID != nil {
				if cachedName, ok := p.cache.Load(*assignment.Properties.RoleDefinitionID); ok {
					roleName = cachedName.(string)
				} else {
					roleName, err = getRoleDefinition(ctx, clients.RoleDefClient, *assignment.Properties.RoleDefinitionID)
					if err == nil && roleName != "" {
						p.cache.Store(*assignment.Properties.RoleDefinitionID, roleName)
					}
				}
			}

			details := &types.RoleAssignmentDetails{
				ID:               *assignment.ID,
				Name:             *assignment.Name,
				PrincipalID:      *assignment.Properties.PrincipalID,
				PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
				RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
				RoleDisplayName:  roleName,
				Scope:            *assignment.Properties.Scope,
				ScopeType:        scopeType,
				ScopeDisplayName: scopeDisplayName,
				SubscriptionID:   subscriptionID,
				SubscriptionName: subscriptionName,
				Properties:       make(map[string]interface{}),
			}
			assignments = append(assignments, details)
		}
	}

	slog.Debug(fmt.Sprintf("Found %d role assignments for %s: %s", assignmentCount, scopeType, scopeDisplayName))
	return assignments, nil
}

// ProcessResourceGroupAssignments processes role assignments for a resource group
func ProcessResourceGroupAssignments(ctx context.Context, clients *ClientSet, rg *armresources.ResourceGroup) ([]*types.RoleAssignmentDetails, error) {
	processor := NewRoleAssignmentProcessor()
	subID := ExtractSubscriptionID(*rg.ID)

	slog.Debug(fmt.Sprintf("Processing resource group: %s", *rg.Name))

	assignments, err := processor.ProcessRoleAssignments(
		ctx,
		clients,
		*rg.ID,
		"ResourceGroup",
		*rg.Name,
		subID,
		"", // Subscription name can be looked up if needed
	)

	if err != nil {
		return nil, fmt.Errorf("failed to process resource group %s: %v", *rg.Name, err)
	}

	return assignments, nil
}

// GetResourceGroupRoleAssignments retrieves role assignments for all resource groups
func GetResourceGroupRoleAssignments(ctx context.Context, resourceClient *armresources.Client, authClient *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	logger := logs.NewStageLogger(ctx, opts, "GetResourceGroupRoleAssignments")

	// Initialize clients
	clients, err := InitializeClients(subscriptionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %v", err)
	}

	// Create worker pool for processing resource groups
	config := DefaultWorkerConfig()
	pool := NewWorkerPool(config, clients, ProcessResourceGroupAssignments)

	// Create input channel for resource groups
	rgChan := make(chan *armresources.ResourceGroup, config.BatchSize)

	// Start feeding resource groups
	go func() {
		defer close(rgChan)
		pager := clients.ResourceGroupsClient.NewListPager(nil)

		rgCount := 0
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				logger.Error("Error listing resource groups", slog.String("error", err.Error()))
				return
			}

			for _, group := range page.Value {
				rgCount++
				select {
				case rgChan <- group:
					logger.Debug(fmt.Sprintf("Queued resource group: %s", *group.Name))
				case <-ctx.Done():
					return
				}
			}
		}
		message.Info("Found %d resource groups to process", rgCount)
	}()

	// Process resource groups with logging
	assignments, err := pool.ProcessWithLogging(ctx, rgChan, "resource group role assignments")
	if err != nil {
		return nil, fmt.Errorf("error processing resource groups: %v", err)
	}

	message.Info("Successfully processed %d role assignments", len(assignments))
	return assignments, nil
}

// Helper functions

// getRoleDefinition gets the display name for a role definition
func getRoleDefinition(ctx context.Context, client *armauthorization.RoleDefinitionsClient, roleDefID string) (string, error) {
	logger := logs.NewStageLogger(ctx, opts, "GetRoleDefinition")
	parts := strings.Split(roleDefID, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid role definition ID format")
	}
	roleName := parts[len(parts)-1]

	def, err := client.GetByID(ctx, roleDefID, nil)
	if err != nil {
		logger.Debug("Failed to get role definition for ID %s: %v", roleDefID, err)
		return roleName, err
	}

	if def.Properties != nil && def.Properties.RoleName != nil {
		return *def.Properties.RoleName, nil
	}

	return roleName, nil
}

// getAssignmentPrincipalType safely extracts the principal type from role assignment properties
func getAssignmentPrincipalType(props *armauthorization.RoleAssignmentPropertiesWithScope) string {
	if props == nil || props.PrincipalID == nil {
		return "Unknown"
	}

	principalID := *props.PrincipalID

	// Determine principal type based on format and prefixes
	switch {
	case strings.Contains(principalID, "@"):
		return "User"
	case len(principalID) == 36 && strings.Count(principalID, "-") == 4:
		// GUID format checks for different types
		switch {
		case strings.HasPrefix(strings.ToLower(principalID), "f"):
			return "ServicePrincipal"
		case strings.HasPrefix(strings.ToLower(principalID), "g"):
			return "Group"
		default:
			return "SecurityPrincipal"
		}
	case strings.HasPrefix(principalID, "mi-"):
		return "ManagedIdentity"
	default:
		return "Unknown"
	}
}

// ExtractSubscriptionID extracts the subscription ID from a resource ID
func ExtractSubscriptionID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ExtractResourceGroup extracts the resource group name from a resource ID
func ExtractResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// ParseLocationsOption parses the locations option string
func ParseLocationsOption(locationsOpt string) ([]string, error) {
	if strings.EqualFold(locationsOpt, "ALL") {
		return AzureLocations, nil
	}

	locations := strings.Split(locationsOpt, ",")
	for _, location := range locations {
		if !IsValidLocation(location) {
			return nil, fmt.Errorf("invalid location: %s", location)
		}
	}
	return locations, nil
}

// IsValidLocation checks if a location is valid
func IsValidLocation(location string) bool {
	normalizedLocation := strings.ToLower(strings.TrimSpace(location))
	for _, validLocation := range AzureLocations {
		if strings.EqualFold(validLocation, normalizedLocation) {
			return true
		}
	}
	return false
}

// HandleAzureError logs Azure-specific errors with appropriate context
func HandleAzureError(err error, operation string, resourceID string) {
	if err != nil {
		slog.Error(fmt.Sprintf("Azure operation '%s' failed for resource '%s': %v",
			operation,
			resourceID,
			err))
	}
}

// GetSubscriptionName gets a subscription's display name
func GetSubscriptionName(ctx context.Context, client *armsubscriptions.Client, subscriptionID string) (string, error) {
	sub, err := client.Get(ctx, subscriptionID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get subscription details: %v", err)
	}

	if sub.DisplayName != nil {
		return *sub.DisplayName, nil
	}
	return subscriptionID, nil // Return ID as fallback
}

// FormatResourceID formats components into an Azure resource ID
func FormatResourceID(subscriptionID, resourceGroup, resourceType, resourceName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s/%s",
		subscriptionID,
		resourceGroup,
		resourceType,
		resourceName)
}

// ValidateResourceID checks if a resource ID is properly formatted
func ValidateResourceID(resourceID string) error {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 9 || // Minimum parts for a valid resource ID
		!strings.EqualFold(parts[1], "subscriptions") ||
		!strings.EqualFold(parts[3], "resourceGroups") ||
		!strings.EqualFold(parts[5], "providers") {
		return fmt.Errorf("invalid resource ID format: %s", resourceID)
	}
	return nil
}

// ListSubscriptions returns all subscriptions accessible to the user
func ListSubscriptions(ctx context.Context, opts []*types.Option) ([]string, error) {
	logger := logs.NewStageLogger(ctx, opts, "ListSubscriptions")

	// Initialize clients (with empty subscription ID since we're listing all subscriptions)
	clients, err := InitializeClients("", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %v", err)
	}

	var subscriptionIDs []string
	pager := clients.SubscriptionClient.NewListPager(nil)

	logger.Info("Starting to list subscriptions...")

	pageCount := 0
	for pager.More() {
		pageCount++
		message.Info("Fetching page %d of subscriptions...", pageCount)

		page, err := pager.NextPage(ctx)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get page %d", pageCount), slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to list subscriptions: %v", err)
		}

		if page.Value == nil {
			message.Warning("Page %d returned nil value", pageCount)
			continue
		}

		logger.Info(fmt.Sprintf("Processing page %d, found %d subscriptions",
			pageCount, len(page.Value)))

		for i, sub := range page.Value {
			if sub.SubscriptionID == nil {
				message.Warning("Subscription at index %d has nil ID", i)
				continue
			}

			state := "Unknown"
			if sub.State != nil {
				state = string(*sub.State)
			}

			name := "Unknown"
			if sub.DisplayName != nil {
				name = *sub.DisplayName
			}

			logger.Info(fmt.Sprintf("Found subscription: ID=%s, Name=%s, State=%s",
				*sub.SubscriptionID,
				name,
				state))

			subscriptionIDs = append(subscriptionIDs, *sub.SubscriptionID)
		}
	}

	if len(subscriptionIDs) == 0 {
		logger.Error("No accessible subscriptions found. This could be due to insufficient permissions")
		return nil, fmt.Errorf("no accessible subscriptions found")
	}

	message.Info("Total subscriptions found: %d", len(subscriptionIDs))
	message.Info("Summary of all found subscriptions:")
	for i, subID := range subscriptionIDs {
		message.Info("%d. %s", i+1, subID)
	}

	return subscriptionIDs, nil
}

// GetSubscriptionDetails gets details about an Azure subscription
func GetSubscriptionDetails(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) (*armsubscriptions.ClientGetResponse, error) {
	logger := logs.NewStageLogger(ctx, []*types.Option{}, "GetSubscriptionDetails")

	// Initialize clients or reuse existing credentials
	clients, err := InitializeClients(subscriptionID, cred)
	if err != nil {
		logger.Error("Failed to initialize clients", slog.String("subscription", subscriptionID), slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to initialize clients: %v", err)
	}

	sub, err := clients.SubscriptionClient.Get(ctx, subscriptionID, nil)
	if err != nil {
		// Check for specific Azure errors indicating permission issues
		if strings.Contains(err.Error(), "AuthorizationFailed") ||
			strings.Contains(err.Error(), "InvalidAuthenticationToken") ||
			strings.Contains(err.Error(), "403") {
			logger.Error("Access denied for subscription",
				slog.String("subscription", subscriptionID),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("no access to subscription - insufficient permissions")
		}
		logger.Error("Failed to get subscription details",
			slog.String("subscription", subscriptionID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get subscription details: %v", err)
	}

	// Additional check if subscription is disabled/not active
	if sub.State != nil && *sub.State != armsubscriptions.SubscriptionStateEnabled {
		logger.Debug("Subscription is not in enabled state",
			slog.String("subscription", subscriptionID),
			slog.String("state", string(*sub.State)))
		return nil, fmt.Errorf("subscription not enabled (current state: %s)", *sub.State)
	}

	logger.Debug("Successfully validated subscription access",
		slog.String("subscription", subscriptionID),
		slog.String("name", *sub.DisplayName))
	return &sub, nil
}

// GetMgmtGroupRoleAssignments retrieves role assignments for all management groups
func GetMgmtGroupRoleAssignments(ctx context.Context, client *armmanagementgroups.Client, subscription string) ([]*types.RoleAssignmentDetails, error) {
	logger := logs.NewStageLogger(ctx, opts, "GetMgmtGroupRoleAssignments")

	assignments := make([]*types.RoleAssignmentDetails, 0)

	// Create role definitions client for looking up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logger.Error("Failed to get Azure credential for role definitions", slog.String("error", err.Error()))
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		logger.Error("Failed to create role definitions client", slog.String("error", err.Error()))
	}

	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list management groups: %v", err)
		}

		for _, group := range page.Value {
			// Create authorization client
			authClient, err := armauthorization.NewRoleAssignmentsClient(subscription, cred, &arm.ClientOptions{})
			if err != nil {
				logger.Error("Failed to create authorization client for mgmt group", slog.String("error", err.Error()))
				continue
			}

			// Get assignments for this management group
			mgmtAssignmentPager := authClient.NewListForScopePager(*group.ID, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
			for mgmtAssignmentPager.More() {
				assignmentPage, err := mgmtAssignmentPager.NextPage(ctx)
				if err != nil {
					logger.Error("Failed to get assignments for mgmt group %s: %v", *group.ID, err)
					continue
				}

				for _, assignment := range assignmentPage.Value {
					// Get role name if possible
					roleName := ""
					if roleDefClient != nil {
						props := assignment.Properties
						if props != nil && props.RoleDefinitionID != nil {
							roleName, err = getRoleDefinition(ctx, roleDefClient, *props.RoleDefinitionID)
							if err != nil {
								logger.Debug("Could not get role name", slog.String("error", err.Error()))
							}
						}
					}

					details := &types.RoleAssignmentDetails{
						ID:               *assignment.ID,
						Name:             *assignment.Name,
						PrincipalID:      *assignment.Properties.PrincipalID,
						PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
						RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
						RoleDisplayName:  roleName,
						Scope:            *assignment.Properties.Scope,
						ScopeType:        "ManagementGroup",
						ScopeDisplayName: *group.Name,
						SubscriptionID:   subscription,
						Properties:       make(map[string]interface{}),
					}
					assignments = append(assignments, details)
				}
			}
		}
	}

	return assignments, nil
}

// GetSubscriptionRoleAssignments retrieves role assignments at the subscription level
func GetSubscriptionRoleAssignments(ctx context.Context, client *armauthorization.RoleAssignmentsClient, subscriptionID, subscriptionName string) ([]*types.RoleAssignmentDetails, error) {
	logger := logs.NewStageLogger(ctx, opts, "GetSubscriptionRoleAssignments")
	assignments := make([]*types.RoleAssignmentDetails, 0)

	// Get role definition client to look up role names
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logger.Error("Failed to get Azure credential for role definitions", slog.String("error", err.Error()))
	}
	roleDefClient, err := armauthorization.NewRoleDefinitionsClient(cred, &arm.ClientOptions{})
	if err != nil {
		logger.Error("Failed to create role definitions client", slog.String("error", err.Error()))
	}

	// Get subscription role assignments at scope
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscription assignments: %v", err)
		}

		for _, assignment := range page.Value {
			// Get role name if possible
			roleName := ""
			if roleDefClient != nil && assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
				roleName, err = getRoleDefinition(ctx, roleDefClient, *assignment.Properties.RoleDefinitionID)
				if err != nil {
					logger.Debug("Could not get role name", slog.String("error", err.Error()))
				}
			}

			details := &types.RoleAssignmentDetails{
				ID:               *assignment.ID,
				Name:             *assignment.Name,
				PrincipalID:      *assignment.Properties.PrincipalID,
				PrincipalType:    getAssignmentPrincipalType(assignment.Properties),
				RoleDefinitionID: *assignment.Properties.RoleDefinitionID,
				RoleDisplayName:  roleName,
				Scope:            *assignment.Properties.Scope,
				ScopeType:        "Subscription",
				ScopeDisplayName: subscriptionName,
				SubscriptionID:   subscriptionID,
				SubscriptionName: subscriptionName,
				Properties:       make(map[string]interface{}),
			}
			assignments = append(assignments, details)
		}
	}

	return assignments, nil
}

// MakeAzureRestRequest makes an authenticated HTTP request to Azure REST API
func MakeAzureRestRequest(ctx context.Context, method string, url string, cred *azidentity.DefaultAzureCredential) (*http.Response, error) {
	// Get the token for the request
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add auth header
	req.Header.Set("Authorization", "Bearer "+token.Token)

	// Make the request
	client := &http.Client{}
	return client.Do(req)
}

func SafeGetString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// Helper function to safely get boolean values from map
func SafeGetBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}

// GetSubscriptionFromResourceID extracts the subscription ID and name from a resource ID
func GetSubscriptionFromResourceID(resourceID string) (string, string, error) {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "subscriptions") && i+1 < len(parts) {
			subID := parts[i+1]

			// Try to get subscription name
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				return subID, "", nil
			}

			client, err := armsubscriptions.NewClient(cred, &arm.ClientOptions{})
			if err != nil {
				return subID, "", nil
			}

			sub, err := client.Get(context.Background(), subID, nil)
			if err != nil {
				return subID, "", nil
			}

			if sub.DisplayName != nil {
				return subID, *sub.DisplayName, nil
			}

			return subID, "", nil
		}
	}

	return "", "", fmt.Errorf("subscription ID not found in resource ID: %s", resourceID)
}

// ParseAzureResourceID parses an Azure resource ID and returns a map of components
func ParseAzureResourceID(resourceID string) (map[string]string, error) {
	result := make(map[string]string)
	
	if resourceID == "" {
		return nil, fmt.Errorf("resource ID cannot be empty")
	}
	
	parts := strings.Split(strings.TrimPrefix(resourceID, "/"), "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid resource ID format: %s", resourceID)
	}
	
	// Parse key-value pairs from the resource ID
	for i := 0; i < len(parts)-1; i += 2 {
		if i+1 < len(parts) {
			result[parts[i]] = parts[i+1]
		}
	}
	
	return result, nil
}
