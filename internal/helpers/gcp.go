package helpers

// GCPEnvironmentDetails holds all GCP environment information
type GCPEnvironmentDetails struct {
	ScopeType string // "organization", "folder", "project"
	ScopeName string
	ScopeID   string
	Location  string
	Labels    map[string]string
	Resources []*ResourceCount
}
