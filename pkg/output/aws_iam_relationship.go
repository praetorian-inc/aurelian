package output

// AWSIAMRelationship represents an allowed permission edge:
// a principal that can perform an action on a resource.
type AWSIAMRelationship struct {
	Principal AWSIAMResource `json:"principal"`
	Resource  AWSResource    `json:"resource"`
	Action    string         `json:"action"`
}
