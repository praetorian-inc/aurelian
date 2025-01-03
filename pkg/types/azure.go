package types

// ResourceInfo contains information about a single Azure resource
type ResourceInfo struct {
	ID            string
	Name          string
	Type          string
	Location      string
	ResourceGroup string
	Tags          map[string]*string
	Properties    map[string]interface{}
}

// AzureResourceDetails contains detailed information about Azure resources
type AzureResourceDetails struct {
	SubscriptionID   string
	SubscriptionName string
	TenantID         string
	TenantName       string
	Resources        []ResourceInfo
}

// RoleAssignmentDetails captures all information about a role assignment
type RoleAssignmentDetails struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	PrincipalID      string                 `json:"principalId"`
	PrincipalType    string                 `json:"principalType"`
	RoleDefinitionID string                 `json:"roleDefinitionId"`
	RoleDisplayName  string                 `json:"roleDisplayName"`
	Scope            string                 `json:"scope"`
	ScopeType        string                 `json:"scopeType"`
	ScopeDisplayName string                 `json:"scopeDisplayName"`
	SubscriptionID   string                 `json:"subscriptionId"`
	SubscriptionName string                 `json:"subscriptionName"`
	Properties       map[string]interface{} `json:"properties"`
}
