package options

import "github.com/praetorian-inc/janus-framework/pkg/chain/cfg"

// Neo4jURI returns the connection string parameter for the Neo4j database
func Neo4jURI() cfg.Param {
	return cfg.NewParam[string]("neo4j-uri", "Neo4j connection URI").
		WithDefault("bolt://localhost:7687")
}

// Neo4jUsername returns the username parameter for Neo4j authentication
func Neo4jUsername() cfg.Param {
	return cfg.NewParam[string]("neo4j-username", "Neo4j authentication username").
		WithDefault("neo4j")
}

// Neo4jPassword returns the password parameter for Neo4j authentication
func Neo4jPassword() cfg.Param {
	return cfg.NewParam[string]("neo4j-password", "Neo4j authentication password").
		WithDefault("neo4j")
}

func Neo4jOptions() []cfg.Param {
	return []cfg.Param{
		Neo4jURI(),
		Neo4jUsername(),
		Neo4jPassword(),
	}
}

func Query() cfg.Param {
	return cfg.NewParam[[]string]("query", "Query to run against the graph database").
		WithDefault([]string{"all"}).
		AsRequired()
}

func List() cfg.Param {
	return cfg.NewParam[bool]("list", "List the available queries").
		WithDefault(false)
}
