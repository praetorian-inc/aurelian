package extraction

import (
	"fmt"
	"strings"
)

// ParseAzureResourceID parses a standard Azure resource ID into its components.
// Input format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}[/{subtype}/{subname}...]
// Returns subscriptionID, resourceGroup, and a map of resource type segments to their values.
func ParseAzureResourceID(id string) (subscriptionID, resourceGroup string, segments map[string]string, err error) {
	if id == "" {
		return "", "", nil, fmt.Errorf("resource ID cannot be empty")
	}

	id = strings.TrimPrefix(id, "/")
	parts := strings.Split(id, "/")

	// Minimum: subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
	if len(parts) < 8 {
		return "", "", nil, fmt.Errorf("invalid Azure resource ID: too few segments")
	}

	if !strings.EqualFold(parts[0], "subscriptions") {
		return "", "", nil, fmt.Errorf("invalid Azure resource ID: expected 'subscriptions' prefix")
	}
	subscriptionID = parts[1]

	if !strings.EqualFold(parts[2], "resourceGroups") {
		return "", "", nil, fmt.Errorf("invalid Azure resource ID: expected 'resourceGroups'")
	}
	resourceGroup = parts[3]

	if !strings.EqualFold(parts[4], "providers") {
		return "", "", nil, fmt.Errorf("invalid Azure resource ID: expected 'providers'")
	}

	// Skip parts[5] (provider namespace like "Microsoft.Compute")
	// Parse remaining parts as type/name pairs
	segments = make(map[string]string)
	for i := 6; i < len(parts)-1; i += 2 {
		segments[parts[i]] = parts[i+1]
	}

	return subscriptionID, resourceGroup, segments, nil
}

// ResourceTypeFromID extracts the top-level Azure resource type from a full resource ID.
// For "/subscriptions/.../providers/Microsoft.Compute/virtualMachines/my-vm" returns "Microsoft.Compute/virtualMachines".
func ResourceTypeFromID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("resource ID cannot be empty")
	}

	trimmed := strings.TrimPrefix(id, "/")
	parts := strings.Split(trimmed, "/")

	if len(parts) < 8 {
		return "", fmt.Errorf("invalid Azure resource ID: too few segments")
	}

	// parts[5] = provider namespace (e.g. "Microsoft.Compute")
	// parts[6] = resource type (e.g. "virtualMachines")
	return parts[5] + "/" + parts[6], nil
}
