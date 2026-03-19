package privescnew

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/praetorian-inc/aurelian/pkg/graph"
)

// mockGraphDB is a minimal mock for testing Neo4jQueryer without a real Neo4j.
type mockGraphDB struct {
	lastCypher string
	lastParams map[string]any
	result     *graph.QueryResult
	err        error
}

func (m *mockGraphDB) Query(ctx context.Context, cypher string, params map[string]any) (*graph.QueryResult, error) {
	m.lastCypher = cypher
	m.lastParams = params
	return m.result, m.err
}

func (m *mockGraphDB) CreateNodes(ctx context.Context, nodes []*graph.Node) (*graph.BatchResult, error) {
	return nil, nil
}
func (m *mockGraphDB) CreateRelationships(ctx context.Context, rels []*graph.Relationship) (*graph.BatchResult, error) {
	return nil, nil
}
func (m *mockGraphDB) VerifyConnectivity(ctx context.Context) error { return nil }
func (m *mockGraphDB) Close() error                                 { return nil }

func TestNeo4jQueryerDelegatesToCompiler(t *testing.T) {
	mock := &mockGraphDB{
		result: &graph.QueryResult{
			Records: []map[string]interface{}{
				{"path": dbtype.Path{
					Nodes: []dbtype.Node{
						{Labels: []string{"Principal"}, Props: map[string]any{"arn": "arn:aws:iam::123456:role/Admin"}},
						{Labels: []string{"ManagedPolicy"}, Props: map[string]any{"arn": "arn:aws:iam::123456:policy/MyPolicy"}},
					},
					Relationships: []dbtype.Relationship{
						{Type: "IAM_CREATEPOLICYVERSION"},
					},
				}},
			},
		},
	}

	q := NewNeo4jQueryer()
	q.db = mock // bypass Connect, inject mock

	query := Match(Principal(), HasPermission("iam:CreatePolicyVersion"), ManagedPolicy())
	results, err := q.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 matched path, got %d", len(results))
	}
	if len(results[0].Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(results[0].Hops))
	}
	hop := results[0].Hops[0]
	if hop.SourceID != "arn:aws:iam::123456:role/Admin" {
		t.Errorf("unexpected source: %s", hop.SourceID)
	}
	if hop.TargetID != "arn:aws:iam::123456:policy/MyPolicy" {
		t.Errorf("unexpected target: %s", hop.TargetID)
	}
	if len(hop.Actions) != 1 || hop.Actions[0] != "IAM_CREATEPOLICYVERSION" {
		t.Errorf("unexpected actions: %v", hop.Actions)
	}

	wantCypher := "MATCH path = (n0)-[r0]->(n1)\n" +
		"WHERE n0._resourceType IN ['AWS::IAM::User', 'AWS::IAM::Role', 'AWS::IAM::Group']\n" +
		"  AND type(r0) = 'IAM_CREATEPOLICYVERSION'\n" +
		"  AND n1._resourceType = 'AWS::IAM::ManagedPolicy'\n" +
		"RETURN path"
	if mock.lastCypher != wantCypher {
		t.Errorf("Cypher mismatch.\ngot:  %s\nwant: %s", mock.lastCypher, wantCypher)
	}
}

func TestNeo4jQueryerCompileError(t *testing.T) {
	q := NewNeo4jQueryer()
	q.db = &mockGraphDB{}

	badQuery := Match(Node{Kind: "Unknown"}, HasPermission("foo:Bar"), Principal())
	_, err := q.Query(context.Background(), badQuery)
	if err == nil {
		t.Fatal("expected error for unknown node kind, got nil")
	}
}

func TestNeo4jQueryerCloseNilDB(t *testing.T) {
	q := NewNeo4jQueryer()
	if err := q.Close(); err != nil {
		t.Fatalf("Close() on nil db should not error: %v", err)
	}
}
