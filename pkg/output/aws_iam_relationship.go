package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AWSIAMRelationship represents an allowed permission edge:
// a principal that can perform an action on a resource.
type AWSIAMRelationship struct {
	model.BaseAurelianModel

	Principal AWSIAMResource `json:"principal"`
	Resource  AWSResource    `json:"resource"`
	Action    string         `json:"action"`
}
