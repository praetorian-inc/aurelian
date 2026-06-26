package enumeration

import (
	"fmt"
	"strings"
)

func newResourceIDError(resourceType, resourceID, want string) error {
	return fmt.Errorf("resource ID %q for %s must be %s", resourceID, resourceType, want)
}

func pathSegment(resourceID, segment string) (string, bool) {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	for i, part := range parts {
		if part == segment && i+1 < len(parts) {
			return parts[i+1], true
		}
	}
	return "", false
}

func lastPathPart(resourceID string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	if len(parts) == 0 {
		return resourceID
	}
	return parts[len(parts)-1]
}

func fullGCPResourceName(projectID, resourceID string) string {
	if strings.HasPrefix(resourceID, "projects/") {
		return resourceID
	}
	return "projects/" + projectID + "/" + strings.TrimPrefix(resourceID, "/")
}
