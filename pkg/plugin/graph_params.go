package plugin

// GraphOutputBase provides reusable Neo4j connection parameters.
// Embed in any module config that needs graph output.
// Usage: type MyConfig struct { plugin.GraphOutputBase }
type GraphOutputBase struct {
	Neo4jURI      string `param:"neo4j-uri" desc:"Neo4j connection URI (e.g., bolt://localhost:7687)" default:""`
	Neo4jUsername string `param:"neo4j-username" desc:"Neo4j username" default:"neo4j"`
	Neo4jPassword string `param:"neo4j-password" desc:"Neo4j password" default:"neo4j" sensitive:"true"`
}
