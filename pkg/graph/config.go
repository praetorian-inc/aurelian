package graph

// Config holds connection parameters for graph database
type Config struct {
	URI      string                 // Neo4j URI (bolt://localhost:7687)
	Username string                 // Authentication username
	Password string                 // Authentication password
	Options  map[string]interface{} // Additional driver options
}

// NewConfig creates a Config with sensible defaults
func NewConfig(uri, username, password string) *Config {
	return &Config{
		URI:      uri,
		Username: username,
		Password: password,
		Options: map[string]interface{}{
			"max_connection_lifetime":        3600, // seconds
			"max_connection_pool_size":       50,
			"connection_acquisition_timeout": 60, // seconds
		},
	}
}
