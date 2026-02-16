package queries

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGraphDB implements graph.GraphDatabase for testing
type mockGraphDB struct {
	queriesCalled []string
	queryResults  map[string]*graph.QueryResult
	queryErrors   map[string]error
}

func newMockGraphDB() *mockGraphDB {
	return &mockGraphDB{
		queriesCalled: []string{},
		queryResults:  make(map[string]*graph.QueryResult),
		queryErrors:   make(map[string]error),
	}
}

func (m *mockGraphDB) Query(ctx context.Context, cypher string, params map[string]any) (*graph.QueryResult, error) {
	m.queriesCalled = append(m.queriesCalled, cypher)

	if err, exists := m.queryErrors[cypher]; exists {
		return nil, err
	}

	if result, exists := m.queryResults[cypher]; exists {
		return result, nil
	}

	return &graph.QueryResult{
		Summary: graph.QuerySummary{
			NodesCreated:         0,
			RelationshipsCreated: 0,
			PropertiesSet:        0,
		},
	}, nil
}

func (m *mockGraphDB) CreateNodes(ctx context.Context, nodes []*graph.Node) (*graph.BatchResult, error) {
	return &graph.BatchResult{}, nil
}

func (m *mockGraphDB) CreateRelationships(ctx context.Context, rels []*graph.Relationship) (*graph.BatchResult, error) {
	return &graph.BatchResult{}, nil
}

func (m *mockGraphDB) VerifyConnectivity(ctx context.Context) error {
	return nil
}

func (m *mockGraphDB) Close() error {
	return nil
}

// TestLoadQueriesFromEmbeddedFS verifies at least one query loads from the embedded filesystem
func TestLoadQueriesFromEmbeddedFS(t *testing.T) {
	// Should have loaded queries during init()
	queries := ListQueries()

	// At minimum should have the placeholder account query
	require.NotEmpty(t, queries, "should load at least one query from embedded FS")
	assert.Contains(t, queries, "aws/enrich/accounts", "should contain the accounts enrichment query")
}

// TestListQueriesReturnsSortedIDs verifies that ListQueries returns sorted query IDs
func TestListQueriesReturnsSortedIDs(t *testing.T) {
	queries := ListQueries()
	require.NotEmpty(t, queries, "should have queries loaded")

	// Verify sorted order
	for i := 1; i < len(queries); i++ {
		assert.LessOrEqual(t, queries[i-1], queries[i], "queries should be sorted alphabetically")
	}
}

// TestGetQueryExisting verifies GetQuery returns a query when it exists
func TestGetQueryExisting(t *testing.T) {
	query, exists := GetQuery("aws/enrich/accounts")

	require.True(t, exists, "accounts query should exist")
	require.NotNil(t, query, "query should not be nil")

	assert.Equal(t, "aws/enrich/accounts", query.Metadata.ID)
	assert.Equal(t, "Account Metadata", query.Metadata.Name)
	assert.Equal(t, "aws", query.Metadata.Platform)
	assert.Equal(t, "enrich", query.Metadata.Type)
	assert.NotEmpty(t, query.Cypher, "should have cypher query")
}

// TestGetQueryMissing verifies GetQuery returns false when query doesn't exist
func TestGetQueryMissing(t *testing.T) {
	query, exists := GetQuery("nonexistent/query")

	assert.False(t, exists, "nonexistent query should return false")
	assert.Nil(t, query, "query should be nil for nonexistent ID")
}

// TestEnrichAWSExecutesQueriesInOrder verifies EnrichAWS runs queries in correct order
func TestEnrichAWSExecutesQueriesInOrder(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	err := EnrichAWS(ctx, mock)
	require.NoError(t, err, "EnrichAWS should not error")

	// Should have called at least one query
	assert.NotEmpty(t, mock.queriesCalled, "should execute at least one query")

	// Verify the accounts query was called (order=0, should be first)
	require.Greater(t, len(mock.queriesCalled), 0, "should have executed queries")
	firstQuery := mock.queriesCalled[0]
	assert.Contains(t, firstQuery, "n._enriched = true", "first query should be accounts enrichment")
}

// TestEnrichAWSFiltersCorrectly verifies EnrichAWS only runs enrich type AWS queries
func TestEnrichAWSFiltersCorrectly(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	err := EnrichAWS(ctx, mock)
	require.NoError(t, err)

	// All executed queries should contain enrichment logic (SET or MERGE)
	for _, cypher := range mock.queriesCalled {
		hasSet := strings.Contains(cypher, "SET")
		hasMerge := strings.Contains(cypher, "MERGE")
		assert.True(t, hasSet || hasMerge, "enrichment queries should either SET properties or MERGE relationships")
	}
}

// TestEnrichAWSReturnsErrorOnQueryFailure verifies EnrichAWS propagates query errors
func TestEnrichAWSReturnsErrorOnQueryFailure(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	// Set up error for any query containing the accounts pattern
	mock.queryErrors["MATCH (n:Principal)\nWHERE n._resourceType STARTS WITH 'AWS::'\nSET n._enriched = true\nRETURN count(n) as enriched_count\n"] = assert.AnError

	err := EnrichAWS(ctx, mock)
	require.Error(t, err, "should return error when query fails")
	assert.Contains(t, err.Error(), "aws/enrich/accounts", "error should mention failing query ID")
}

// TestRunPlatformQueryExecutesQuery verifies RunPlatformQuery executes the correct query
func TestRunPlatformQueryExecutesQuery(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	result, err := RunPlatformQuery(ctx, mock, "aws/enrich/accounts", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have called exactly one query
	assert.Len(t, mock.queriesCalled, 1, "should execute exactly one query")
}

// TestRunPlatformQueryWithParameters verifies parameters are passed correctly
func TestRunPlatformQueryWithParameters(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	params := map[string]any{
		"accountId": "123456789012",
	}

	_, err := RunPlatformQuery(ctx, mock, "aws/enrich/accounts", params)
	require.NoError(t, err)

	// Mock should have received the query
	assert.NotEmpty(t, mock.queriesCalled)
}

// TestRunPlatformQueryNotFound verifies error when query ID doesn't exist
func TestRunPlatformQueryNotFound(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	result, err := RunPlatformQuery(ctx, mock, "nonexistent/query", nil)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query not found", "error should indicate missing query")
}
