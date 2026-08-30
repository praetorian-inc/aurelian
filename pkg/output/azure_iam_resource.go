package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AzureIAMResource represents Azure IAM data collected by the iam-pull modules.
type AzureIAMResource struct {
	model.BaseAurelianModel

	// DataType identifies which collector produced this data.
	// One of: "entra", "pim", "rbac", "mgmt-groups", "consolidated"
	DataType string `json:"data_type"`

	// Data holds the typed collection result (EntraIDData, PIMData, RBACData,
	// ManagementGroupData, or AzureIAMConsolidated).
	Data any `json:"data"`
}

// NewAzureIAMResource creates an AzureIAMResource.
func NewAzureIAMResource(dataType string, data any) AzureIAMResource {
	return AzureIAMResource{
		DataType: dataType,
		Data:     data,
	}
}
