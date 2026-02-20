package aws

import (
	"encoding/json"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"strings"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// NodeFromGaadUser creates a graph node from an IAM User
// Labels: ["User", "Principal", "AWS::IAM::User"]
// UniqueKey: ["Arn"]
func NodeFromGaadUser(user types.UserDetail) *graph.Node {
	props := flattenStruct(user)
	props["_type"] = "User"
	props["_resourceType"] = "AWS::IAM::User"

	return &graph.Node{
		Labels:     []string{"User", "Principal", "AWS::IAM::User"},
		Properties: props,
		UniqueKey:  []string{"Arn"},
	}
}

// NodeFromGaadRole creates a graph node from an IAM Role
// Labels: ["Role", "Principal", "AWS::IAM::Role"]
// UniqueKey: ["Arn"]
// Extracts trusted_services from AssumeRolePolicyDocument if present
func NodeFromGaadRole(role types.RoleDetail) *graph.Node {
	props := flattenStruct(role)
	props["_type"] = "Role"
	props["_resourceType"] = "AWS::IAM::Role"

	// Extract trusted services from AssumeRolePolicyDocument
	if role.AssumeRolePolicyDocument.Statement != nil {
		var trustedServices []string
		for _, stmt := range *role.AssumeRolePolicyDocument.Statement {
			if stmt.Principal != nil && stmt.Principal.Service != nil {
				trustedServices = append(trustedServices, *stmt.Principal.Service...)
			}
		}
		if len(trustedServices) > 0 {
			props["trusted_services"] = trustedServices
		}
	}

	return &graph.Node{
		Labels:     []string{"Role", "Principal", "AWS::IAM::Role"},
		Properties: props,
		UniqueKey:  []string{"Arn"},
	}
}

// NodeFromGaadGroup creates a graph node from an IAM Group
// Labels: ["Group", "Principal", "AWS::IAM::Group"]
// UniqueKey: ["Arn"]
func NodeFromGaadGroup(group types.GroupDetail) *graph.Node {
	props := flattenStruct(group)
	props["_type"] = "Group"
	props["_resourceType"] = "AWS::IAM::Group"

	return &graph.Node{
		Labels:     []string{"Group", "Principal", "AWS::IAM::Group"},
		Properties: props,
		UniqueKey:  []string{"Arn"},
	}
}

// NodeFromAWSResource creates a graph node from an AWSResource
// Labels derived from ResourceType: ["ShortName", "Resource", "AWS::S3::Bucket"]
// UniqueKey: ["ARN"]
func NodeFromAWSResource(cr output.AWSResource) *graph.Node {
	props := flattenStruct(cr)
	props["_type"] = "Resource"
	props["_resourceType"] = cr.ResourceType

	// Parse resource type to get short name
	parts := parseResourceType(cr.ResourceType)
	var labels []string
	if len(parts) >= 3 {
		labels = []string{parts[2], "Resource", cr.ResourceType}
	} else {
		labels = []string{"Resource", cr.ResourceType}
	}

	return &graph.Node{
		Labels:     labels,
		Properties: props,
		UniqueKey:  []string{"arn"},
	}
}

// NodeFromAWSIAMResource creates a graph node from an AWSIAMResource.
// For IAM types with OriginalData, it delegates to the existing NodeFromGaad*
// functions to preserve property naming (PascalCase). For non-IAM resources,
// it falls back to NodeFromAWSResource.
func NodeFromAWSIAMResource(resource output.AWSIAMResource) *graph.Node {
	// If we have the original GAAD data, use the existing typed converters
	if resource.OriginalData != nil {
		switch data := resource.OriginalData.(type) {
		case types.UserDetail:
			return NodeFromGaadUser(data)
		case types.RoleDetail:
			return NodeFromGaadRole(data)
		case types.GroupDetail:
			return NodeFromGaadGroup(data)
		case types.ManagedPolicyDetail:
			// Policies don't have a GAAD node type; use AWSResource style
			return NodeFromAWSResource(resource.AWSResource)
		}
	}

	// Fallback: non-IAM resources or missing OriginalData
	return NodeFromAWSResource(resource.AWSResource)
}

// NodeFromServicePrincipal creates a graph node from a service principal string
// Labels: ["ServicePrincipal", "Principal"]
// UniqueKey: ["service"]
func NodeFromServicePrincipal(serviceName string) *graph.Node {
	return &graph.Node{
		Labels: []string{"ServicePrincipal", "Principal"},
		Properties: map[string]interface{}{
			"service": serviceName,
			"_type":   "ServicePrincipal",
		},
		UniqueKey: []string{"service"},
	}
}

// RelationshipFromFullResult creates a relationship from a FullResult
// Type-switches on Principal to create principal node
// Converts Resource to node via ToAWSResource()
// Relationship type from normalizeActionToRelType(action)
func RelationshipFromFullResult(result iampkg.FullResult) *graph.Relationship {
	var startNode *graph.Node

	// Type-switch on Principal to create the appropriate node
	switch p := result.Principal.(type) {
	case *types.UserDetail:
		startNode = NodeFromGaadUser(*p)
	case *types.RoleDetail:
		startNode = NodeFromGaadRole(*p)
	case *types.GroupDetail:
		startNode = NodeFromGaadGroup(*p)
	case string:
		// Service principal
		startNode = NodeFromServicePrincipal(p)
	default:
		// Fallback for unknown types
		startNode = &graph.Node{
			Labels:     []string{"UnknownPrincipal", "Principal"},
			Properties: map[string]interface{}{"raw_principal": p},
			UniqueKey:  []string{"raw_principal"},
		}
	}

	// Convert resource to AWSResource and create end node
	var endNode *graph.Node
	if result.Resource != nil {
		// For IAM principals, use GAAD-style nodes to match existing GAAD-created nodes
		switch result.Resource.TypeName {
		case "AWS::IAM::User":
			endNode = &graph.Node{
				Labels:     []string{"User", "Principal", "AWS::IAM::User"},
				Properties: map[string]interface{}{"Arn": result.Resource.Arn.String()},
				UniqueKey:  []string{"Arn"},
			}
		case "AWS::IAM::Role":
			endNode = &graph.Node{
				Labels:     []string{"Role", "Principal", "AWS::IAM::Role"},
				Properties: map[string]interface{}{"Arn": result.Resource.Arn.String()},
				UniqueKey:  []string{"Arn"},
			}
		case "AWS::IAM::Group":
			endNode = &graph.Node{
				Labels:     []string{"Group", "Principal", "AWS::IAM::Group"},
				Properties: map[string]interface{}{"Arn": result.Resource.Arn.String()},
				UniqueKey:  []string{"Arn"},
			}
		case "AWS::IAM::Policy":
			// IAM Policies are discovered via CloudControl, not GAAD
			// Use AWSResource style with Resource label
			cloudResource := output.AWSResourceFromERD(result.Resource)
			endNode = NodeFromAWSResource(cloudResource)
		default:
			cloudResource := output.AWSResourceFromERD(result.Resource)
			endNode = NodeFromAWSResource(cloudResource)
		}
	} else {
		// Fallback for nil resource
		endNode = &graph.Node{
			Labels:     []string{"UnknownResource"},
			Properties: map[string]interface{}{},
			UniqueKey:  []string{},
		}
	}

	// Create relationship with normalized action type
	relType := normalizeActionToRelType(result.Action)

	return &graph.Relationship{
		Type:       relType,
		Properties: map[string]interface{}{"action": result.Action},
		StartNode:  startNode,
		EndNode:    endNode,
	}
}

// flattenStruct converts a Go struct to map[string]interface{} with only Neo4j-compatible values.
// Neo4j properties must be primitive types (string, number, bool) or arrays of primitives.
// Nested maps/objects are serialized as JSON strings to preserve data without losing queryability.
func flattenStruct(obj interface{}) map[string]interface{} {
	data, err := json.Marshal(obj)
	if err != nil {
		return map[string]interface{}{}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return map[string]interface{}{}
	}

	result := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if neo4jSafe := toNeo4jProperty(v); neo4jSafe != nil {
			result[k] = neo4jSafe
		}
	}
	return result
}

// toNeo4jProperty converts a value to a Neo4j-compatible property value.
// Returns nil for values that cannot be stored (empty arrays of objects, nil values).
func toNeo4jProperty(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return val
	case float64: // JSON numbers are float64
		return val
	case bool:
		return val
	case []interface{}:
		return toNeo4jArray(val)
	default:
		// Nested maps/objects: serialize as JSON string
		data, err := json.Marshal(val)
		if err != nil {
			return nil
		}
		s := string(data)
		if s == "{}" || s == "null" {
			return nil
		}
		return s
	}
}

// toNeo4jArray converts an array to a Neo4j-compatible array.
// Arrays of primitives (strings, numbers) are kept as-is.
// Arrays of objects are serialized as JSON string.
func toNeo4jArray(arr []interface{}) interface{} {
	if len(arr) == 0 {
		return nil
	}
	// Check if all elements are strings
	allStrings := true
	for _, elem := range arr {
		if _, ok := elem.(string); !ok {
			allStrings = false
			break
		}
	}
	if allStrings {
		strs := make([]string, len(arr))
		for i, elem := range arr {
			strs[i] = elem.(string)
		}
		return strs
	}
	// Check if all elements are numbers
	allNumbers := true
	for _, elem := range arr {
		if _, ok := elem.(float64); !ok {
			allNumbers = false
			break
		}
	}
	if allNumbers {
		return arr
	}
	// Mixed or complex arrays: serialize as JSON string
	data, err := json.Marshal(arr)
	if err != nil {
		return nil
	}
	s := string(data)
	if s == "[]" || s == "null" {
		return nil
	}
	return s
}

// parseResourceType splits "AWS::S3::Bucket" into ["AWS", "S3", "Bucket"]
func parseResourceType(rt string) []string {
	return strings.Split(rt, "::")
}

// normalizeActionToRelType converts "s3:GetObject" to "S3_GETOBJECT"
func normalizeActionToRelType(action string) string {
	// Replace colon with underscore and convert to uppercase
	normalized := strings.ReplaceAll(action, ":", "_")
	return strings.ToUpper(normalized)
}
