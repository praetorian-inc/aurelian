package templates

// ARGQueryTemplate represents a single Azure Resource Graph query template
type ARGQueryTemplate struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Query       string   `yaml:"query"`
	Category    string   `yaml:"category"`
	References  []string `yaml:"references"`
	TriageNotes string   `yaml:"triageNotes,omitempty"`
}

// ARGQueryResult represents a standardized result from an ARG query
type ARGQueryResult struct {
	TemplateID      string                 `json:"templateId"`
	TemplateDetails *ARGQueryTemplate      `json:"templateDetails"`
	Name            string                 `json:"name"`
	ResourceID      string                 `json:"resourceId"`
	ResourceName    string                 `json:"resourceName"`
	ResourceType    string                 `json:"resourceType"`
	Location        string                 `json:"location"`
	SubscriptionID  string                 `json:"subscriptionId"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
	Commands        []Command              `json:"commands,omitempty"` // Array of commands and outputs
}

// ARGTemplateLoader handles loading and validating ARG query templates
type ARGTemplateLoader struct {
	Templates []*ARGQueryTemplate
}

// Command represents the input and output of a command that requires manual triage
type Command struct {
	Command                   string `json:"command"`
	Description               string `json:"description"`
	ExpectedOutputDescription string `json:"expected_output_description"`
	ActualOutput              string `json:"actual_output"`
	ExitCode                  int    `json:"exit_code"`
	Error                     string `json:"error,omitempty"`
}
