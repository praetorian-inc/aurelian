package types

// ResourceInfo contains information about a single Azure resource
type ResourceInfo struct {
	ID            string
	Name          string
	Type          string
	Location      string
	ResourceGroup string
	Subscription  string
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

// ResourceScanInput holds the subscription and resource type to scan
type ResourceScanInput struct {
	Subscription string
	ResourceType string
}

// DevOpsScanConfig contains Azure DevOps specific scanning configuration
type DevOpsScanConfig struct {
	Organization string `json:"organization"`
	Project      string `json:"project"`
	TempDir      string `json:"tempDir"`
}

// DevOpsVariableGroup represents an Azure DevOps variable group
type DevOpsVariableGroup struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Variables   map[string]struct {
		Value    string `json:"value"`
		IsSecret bool   `json:"isSecret"`
	} `json:"variables"`
}

// DevOpsServiceConnection represents an Azure DevOps service connection
type DevOpsServiceConnection struct {
	Id          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
}

type DevOpsPipelineJob struct {
	Id        int               `json:"id"`
	Name      string            `json:"name"`
	Variables map[string]string `json:"variables"`
}

type DevOpsRepo struct {
	Id            string `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"defaultBranch"`
	WebUrl        string `json:"webUrl"`
}

type DevOpsPipeline struct {
	Id     int    `json:"id"`
	Name   string `json:"name"`
	Folder string `json:"folder"`
}

// AzureStorageAccountDetail represents details about a publicly accessible storage account
type AzureStorageAccountDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	DefaultAction       string `json:"defaultAction"`
}

// AppServiceDetail represents details about a publicly accessible app service
type AppServiceDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess bool   `json:"publicNetworkAccess"`
	Kind                string `json:"kind"`
}

// SqlServerDetail represents details about a publicly accessible SQL server
type SqlServerDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	MinimalTlsVersion   string `json:"minimalTlsVersion"`
	Scope               string `json:"scope"`
}

// VirtualMachineDetail represents details about a publicly accessible virtual machine.
type VirtualMachineDetail struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Location    string `json:"location"`
	PublicIP    string `json:"publicIp"`
	HasPublicIP bool   `json:"hasPublicIp"`
	OpenPorts   string `json:"openPorts,omitempty"`
	OsType      string `json:"osType"`
}

// ContainerRegistryDetail represents details about a publicly accessible ACR
type ContainerRegistryDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	AdminEnabled        bool   `json:"adminEnabled"`
	Sku                 string `json:"sku"`
	LoginServer         string `json:"loginServer"`
}

// RedisCacheDetail represents details about a publicly accessible Redis Cache
type RedisCacheDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	Sku                 string `json:"sku"`
	EnableNonSslPort    bool   `json:"enableNonSslPort"`
	MinimalTlsVersion   string `json:"minimalTlsVersion"`
	HostName            string `json:"hostName"`
}

// ServiceBusDetail represents details about a publicly accessible Service Bus namespace
type ServiceBusDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                string `json:"type"`
	Location            string `json:"location"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	DefaultAction       string `json:"defaultAction"`
	Sku                 string `json:"sku"`
	Endpoint            string `json:"endpoint"`
	ZoneRedundant       bool   `json:"zoneRedundant"`
}
