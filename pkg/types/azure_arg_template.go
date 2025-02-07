package types

// ARGQueryTemplate represents a single Azure Resource Graph query template
type ARGQueryTemplate struct {
	ID          string `yaml:"id"`           // Unique identifier for the query
	Name        string `yaml:"name"`         // Human readable name
	Description string `yaml:"description"`   // Description of what the query checks for
	Severity    string `yaml:"severity"`      // High, Medium, Low
	Query       string `yaml:"query"`        // The actual ARG query
	Category    string `yaml:"category"`     // Category of resource (e.g., Network, Storage)
	References  []string `yaml:"references"` // Relevant documentation links
}

// ARGQueryResult represents a standardized result from an ARG query
type ARGQueryResult struct {
	TemplateID      string                 `json:"templateId"`
	Name            string                 `json:"name"`
	ResourceID      string                 `json:"resourceId"`
	ResourceName    string                 `json:"resourceName"`
	ResourceType    string                 `json:"resourceType"`
	Location        string                 `json:"location"`
	SubscriptionID  string                 `json:"subscriptionId"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
}

// ARGTemplateLoader handles loading and validating ARG query templates
type ARGTemplateLoader struct {
	Templates []*ARGQueryTemplate
}