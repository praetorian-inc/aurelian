package plugin

import (
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
	"github.com/praetorian-inc/aurelian/pkg/graph/queryer"
)

// GraphOutputBase provides reusable Neo4j connection parameters.
// Embed in any module config that needs graph output.
// Usage: type MyConfig struct { plugin.GraphOutputBase }
type GraphOutputBase struct {
	Neo4jURI      string      `param:"neo4j-uri" desc:"Neo4j connection URI (e.g., bolt://localhost:7687)" default:"" required:"true"`
	Neo4jUsername string      `param:"neo4j-username" desc:"Neo4j username" default:"neo4j"`
	Neo4jPassword string      `param:"neo4j-password" desc:"Neo4j password" default:"neo4j" sensitive:"true"`
	Queryer       dsl.Queryer `param:"dsl-queryer" desc:"Queryer"`
}

func (c *GraphOutputBase) PostBind(_ Config, _ Module) error {
	// prefer caller-provided Queryer
	if c.Queryer != nil {
		return nil
	}

	q := queryer.NewNeo4jQueryer()
	if err := q.Connect(c.Neo4jURI, c.Neo4jUsername, c.Neo4jPassword); err != nil {
		return fmt.Errorf("connecting to Neo4j: %w", err)
	}

	c.Queryer = q
	return nil
}
