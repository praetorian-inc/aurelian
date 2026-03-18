package privescnew

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
)

// Neo4jCompiler compiles Query ASTs into Neo4j Cypher strings.
type Neo4jCompiler struct {
	// NodePredicates maps a node Kind to a function that returns a WHERE clause
	// fragment given the node's alias. If a Kind is missing, compilation fails.
	NodePredicates map[string]func(alias string) string
}

// DefaultNeo4jCompiler returns a compiler with Chariot's standard node-kind mappings.
func DefaultNeo4jCompiler() *Neo4jCompiler {
	return &Neo4jCompiler{
		NodePredicates: map[string]func(alias string) string{
			"Principal": func(a string) string {
				return a + "._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']"
			},
			"ManagedPolicy": func(a string) string {
				return a + "._resourceType = 'AWS::IAM::ManagedPolicy'"
			},
		},
	}
}

// Compile transforms a Query into a Cypher string.
// Aliases are assigned sequentially: n0, r0, n1.
func (c *Neo4jCompiler) Compile(q Query) (string, error) {
	fromAlias := "n0"
	relAlias := "r0"
	toAlias := "n1"

	var wheres []string

	fromPred, ok := c.NodePredicates[q.From.Kind]
	if !ok {
		return "", fmt.Errorf("no predicate for node kind %q", q.From.Kind)
	}
	wheres = append(wheres, fromPred(fromAlias))

	relType := actionToRelType(q.Permission.Action)
	wheres = append(wheres, fmt.Sprintf("type(%s) = '%s'", relAlias, relType))

	toPred, ok := c.NodePredicates[q.To.Kind]
	if !ok {
		return "", fmt.Errorf("no predicate for node kind %q", q.To.Kind)
	}
	wheres = append(wheres, toPred(toAlias))

	cypher := fmt.Sprintf(
		"MATCH path = (%s)-[%s]->(%s)\nWHERE %s\nRETURN path",
		fromAlias, relAlias, toAlias,
		strings.Join(wheres, "\n  AND "),
	)
	return cypher, nil
}

// actionToRelType converts an IAM action to a Neo4j relationship type.
// "iam:CreatePolicyVersion" → "IAM_CREATEPOLICYVERSION"
func actionToRelType(action string) string {
	return strings.ToUpper(strings.ReplaceAll(action, ":", "_"))
}

// Neo4jQueryer implements Queryer by compiling DSL queries to Cypher
// and executing them against a direct Neo4j connection.
type Neo4jQueryer struct {
	compiler *Neo4jCompiler
	db       graph.GraphDatabase
}

// NewNeo4jQueryer creates a Neo4jQueryer with the default compiler.
// Call Connect() before Query().
func NewNeo4jQueryer() *Neo4jQueryer {
	return &Neo4jQueryer{
		compiler: DefaultNeo4jCompiler(),
	}
}

func (q *Neo4jQueryer) Connect(uri, username, password string) error {
	cfg := graph.NewConfig(uri, username, password)
	db, err := adapters.NewNeo4jAdapter(cfg)
	if err != nil {
		return err
	}
	if err := db.VerifyConnectivity(context.Background()); err != nil {
		db.Close()
		return err
	}
	q.db = db
	return nil
}

func (q *Neo4jQueryer) Query(ctx context.Context, query Query) ([]*graph.QueryResult, error) {
	cypher, err := q.compiler.Compile(query)
	if err != nil {
		return nil, err
	}
	result, err := q.db.Query(ctx, cypher, nil)
	if err != nil {
		return nil, err
	}
	return []*graph.QueryResult{result}, nil
}

func (q *Neo4jQueryer) Close() error {
	if q.db != nil {
		return q.db.Close()
	}
	return nil
}
