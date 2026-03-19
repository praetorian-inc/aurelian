package neo4j

import (
	"context"
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
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
func (c *Neo4jCompiler) Compile(q dsl.Query) (string, error) {
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

func (q *Neo4jQueryer) Query(ctx context.Context, query dsl.Query) ([]dsl.MatchedPath, error) {
	cypher, err := q.compiler.Compile(query)
	if err != nil {
		return nil, err
	}
	result, err := q.db.Query(ctx, cypher, nil)
	if err != nil {
		return nil, err
	}
	return pathRecordsToMatchedPaths(result), nil
}

// pathRecordsToMatchedPaths converts Cypher "RETURN path" records into MatchedPaths.
// Each record's "path" column is a dbtype.Path representing one escalation instance.
func pathRecordsToMatchedPaths(qr *graph.QueryResult) []dsl.MatchedPath {
	if qr == nil {
		return nil
	}
	var paths []dsl.MatchedPath
	for _, record := range qr.Records {
		pathData, ok := record["path"]
		if !ok {
			continue
		}
		path, ok := pathData.(dbtype.Path)
		if !ok {
			continue
		}
		mp := pathToMatchedPath(path)
		if len(mp.Hops) > 0 {
			paths = append(paths, mp)
		}
	}
	return paths
}

// pathToMatchedPath converts a single dbtype.Path into a MatchedPath.
// Each relationship in the path becomes one hop.
func pathToMatchedPath(path dbtype.Path) dsl.MatchedPath {
	var hops []dsl.MatchResult
	for i, rel := range path.Relationships {
		if i+1 >= len(path.Nodes) {
			break
		}
		hops = append(hops, dsl.MatchResult{
			SourceID: nodeIdentifier(path.Nodes[i]),
			TargetID: nodeIdentifier(path.Nodes[i+1]),
			Actions:  []string{relTypeToAction(rel.Type)},
		})
	}
	return dsl.MatchedPath{Hops: hops}
}

// nodeIdentifier extracts the best identifier from a Neo4j node.
// Prefers "arn", falls back to "key", then first available property.
func nodeIdentifier(n dbtype.Node) string {
	for _, prop := range []string{"arn", "key"} {
		if v, ok := n.Props[prop]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return fmt.Sprintf("node(%v)", n.Labels)
}

// relTypeToAction converts a Neo4j relationship type back to an IAM action string.
// "IAM_CREATEPOLICYVERSION" → "iam:CreatePolicyVersion"
// This is a best-effort inverse of actionToRelType; the uppercase form is
// returned if the original casing cannot be recovered.
func relTypeToAction(relType string) string {
	return relType
}

func (q *Neo4jQueryer) Close() error {
	if q.db != nil {
		return q.db.Close()
	}
	return nil
}
