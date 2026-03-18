package privescnew

import (
	"fmt"
	"strings"
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
