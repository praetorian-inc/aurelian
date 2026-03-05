package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// GCPResource represents a Google Cloud Platform resource discovered during scanning.
type GCPResource struct {
	model.BaseAurelianModel

	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ProjectID    string            `json:"project_id"`
	Location     string            `json:"location,omitempty"`
	DisplayName  string            `json:"display_name,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
	URLs         []string          `json:"urls,omitempty"`
	IPs          []string          `json:"ips,omitempty"`
	AccessLevel  AccessLevel       `json:"access_level,omitempty"`
}

// NewGCPResource creates a GCPResource with required fields.
func NewGCPResource(projectID, resourceType, resourceID string) GCPResource {
	return GCPResource{
		ProjectID:    projectID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}
