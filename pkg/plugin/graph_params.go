package plugin

import (
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/graph/neo4j"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// GraphOutputBase provides reusable Neo4j connection parameters.
// Embed in any module config that needs graph output.
// Usage: type MyConfig struct { plugin.GraphOutputBase }
type GraphOutputBase struct {
	Neo4jURI      string      `param:"neo4j-uri" desc:"Neo4j connection URI (e.g., bolt://localhost:7687)" default:""`
	Neo4jUsername string      `param:"neo4j-username" desc:"Neo4j username" default:"neo4j"`
	Neo4jPassword string      `param:"neo4j-password" desc:"Neo4j password" default:"neo4j" sensitive:"true"`
	Queryer       dsl.Queryer `param:"neo4j-queryer" desc:"Queryer"`
}

func (c *GraphOutputBase) PostBind(cfg Config, _ Module) error {
	// prefer caller-provided Queryer
	if q, ok := cfg.Args["neo4j-queryer"]; ok {
		queryer, ok := q.(dsl.Queryer)
		if !ok {
			return fmt.Errorf("neo4j-queryer is not a dsl.Queryer")
		}
		c.Queryer = queryer
		return nil
	}

	// We don't want to mark `neo4j-uri` as `required` in the field tag because it isn't required when a Queryer is provided.
	if c.Neo4jURI != "" {
		return fmt.Errorf("neo4j connection URI is required")
	}

	q := neo4j.NewNeo4jQueryer()
	if err := q.Connect(c.Neo4jURI, c.Neo4jUsername, c.Neo4jPassword); err != nil {
		return fmt.Errorf("connecting to Neo4j: %w", err)
	}

	c.Queryer = q
	return nil
}
