package options

import "github.com/praetorian-inc/aurelian/pkg/plugin"

// Neo4jURI returns the connection string parameter for the Neo4j database
func Neo4jURI() plugin.Parameter {
	return plugin.NewParam[string]("neo4j-uri", "Neo4j connection URI",
		plugin.WithDefault("bolt://localhost:7687"),
	)
}

// Neo4jUsername returns the username parameter for Neo4j authentication
func Neo4jUsername() plugin.Parameter {
	return plugin.NewParam[string]("neo4j-username", "Neo4j authentication username",
		plugin.WithDefault("neo4j"),
	)
}

// Neo4jPassword returns the password parameter for Neo4j authentication
func Neo4jPassword() plugin.Parameter {
	return plugin.NewParam[string]("neo4j-password", "Neo4j authentication password",
		plugin.WithDefault("neo4j"),
	)
}

func Neo4jOptions() []plugin.Parameter {
	return []plugin.Parameter{
		Neo4jURI(),
		Neo4jUsername(),
		Neo4jPassword(),
	}
}

func Query() plugin.Parameter {
	return plugin.NewParam[[]string]("query", "Query to run against the graph database",
		plugin.WithDefault([]string{"all"}),
		plugin.WithRequired(),
	)
}

func List() plugin.Parameter {
	return plugin.NewParam[bool]("list", "List the available queries",
		plugin.WithDefault(false),
	)
}
