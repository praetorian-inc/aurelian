package output

import "strings"

// ResourceTypeSlug converts a cloud resource type string into a short, lowercase,
// hyphen-delimited slug suitable for embedding in risk IDs.
//
// Supported formats:
//   - AWS:    "AWS::Lambda::Function"                        → "lambda-function"
//   - Azure:  "Microsoft.Compute/virtualMachines"            → "compute-virtualmachines"
//   - Azure:  "microsoft.compute/virtualmachines" (from ARG) → "compute-virtualmachines"
//   - GCP:    "compute.googleapis.com/Instance"              → "compute-instance"
func ResourceTypeSlug(resourceType string) string {
	if resourceType == "" {
		return ""
	}
	// Normalize to lowercase first — Azure Resource Graph returns lowercase
	// types (e.g., "microsoft.storage/storageaccounts"), while unit tests and
	// ARM IDs may use mixed case ("Microsoft.Storage/storageAccounts").
	lower := strings.ToLower(resourceType)
	switch {
	case strings.HasPrefix(lower, "aws::"):
		// AWS::Lambda::Function → lambda-function
		return strings.ReplaceAll(lower[len("aws::"):], "::", "-")
	case strings.HasPrefix(lower, "microsoft."):
		// microsoft.compute/virtualmachines → compute-virtualmachines
		return strings.ReplaceAll(lower[len("microsoft."):], "/", "-")
	case strings.Contains(lower, ".googleapis.com/"):
		// compute.googleapis.com/instance → compute-instance
		return strings.ReplaceAll(strings.Replace(lower, ".googleapis.com", "", 1), "/", "-")
	default:
		return lower
	}
}
