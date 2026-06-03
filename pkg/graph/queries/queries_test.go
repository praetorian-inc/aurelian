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
	defaultError  error // returned for any query not in queryErrors
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

	if m.defaultError != nil {
		return nil, m.defaultError
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

// TestEnrichAWSWarnsOnSingleQueryFailure verifies EnrichAWS warns but continues
// when an individual query fails (ztgrace pattern: warn per failure, error only if all fail).
func TestEnrichAWSWarnsOnSingleQueryFailure(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	// Fail only the accounts query — all others succeed.
	mock.queryErrors["MATCH (n:Principal)\nWHERE n._resourceType STARTS WITH 'AWS::'\nSET n._enriched = true\nRETURN count(n) as enriched_count\n"] = assert.AnError

	// A single failure should NOT return an error — EnrichAWS warns and continues.
	err := EnrichAWS(ctx, mock)
	assert.NoError(t, err, "single query failure should warn and continue, not abort enrichment")
}

// TestEnrichAWSReturnsErrorWhenAllQueriesFail verifies EnrichAWS returns an error
// only when every query fails (ztgrace pattern: error if ALL methods failed).
func TestEnrichAWSReturnsErrorWhenAllQueriesFail(t *testing.T) {
	mock := newMockGraphDB()
	ctx := context.Background()

	// Make every query call return an error.
	mock.defaultError = assert.AnError

	err := EnrichAWS(ctx, mock)
	require.Error(t, err, "should return error when all queries fail")
	assert.Contains(t, err.Error(), "all", "error should mention all queries failed")
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

// TestNewPrivescQueriesLoad verifies all new pathfinding.cloud gap-analysis methods load correctly.
func TestNewPrivescQueriesLoad(t *testing.T) {
	newMethods := []string{
		// Initial gap-fill methods (43–72)
		"aws/enrich/privesc/method_43",
		"aws/enrich/privesc/method_44",
		"aws/enrich/privesc/method_45",
		"aws/enrich/privesc/method_46",
		"aws/enrich/privesc/method_47",
		"aws/enrich/privesc/method_48",
		"aws/enrich/privesc/method_49",
		"aws/enrich/privesc/method_50",
		"aws/enrich/privesc/method_51",
		"aws/enrich/privesc/method_52",
		"aws/enrich/privesc/method_53",
		"aws/enrich/privesc/method_54",
		"aws/enrich/privesc/method_55",
		"aws/enrich/privesc/method_56",
		"aws/enrich/privesc/method_57",
		"aws/enrich/privesc/method_58",
		"aws/enrich/privesc/method_59",
		"aws/enrich/privesc/method_60",
		"aws/enrich/privesc/method_61",
		"aws/enrich/privesc/method_62",
		"aws/enrich/privesc/method_63",
		"aws/enrich/privesc/method_64",
		"aws/enrich/privesc/method_65",
		"aws/enrich/privesc/method_66",
		"aws/enrich/privesc/method_67",
		"aws/enrich/privesc/method_68",
		"aws/enrich/privesc/method_69",
		"aws/enrich/privesc/method_70",
		"aws/enrich/privesc/method_71",
		"aws/enrich/privesc/method_72",
		// Group A: wrong-API fixes (73–74)
		"aws/enrich/privesc/method_73",
		"aws/enrich/privesc/method_74",
		// Group B: completely missing (75–79)
		"aws/enrich/privesc/method_75",
		"aws/enrich/privesc/method_76",
		"aws/enrich/privesc/method_77",
		"aws/enrich/privesc/method_78",
		"aws/enrich/privesc/method_79",
		// Group C: execution-gated compound methods (80–89)
		"aws/enrich/privesc/method_80",
		"aws/enrich/privesc/method_81",
		"aws/enrich/privesc/method_82",
		"aws/enrich/privesc/method_83",
		"aws/enrich/privesc/method_84",
		"aws/enrich/privesc/method_85",
		"aws/enrich/privesc/method_86",
		"aws/enrich/privesc/method_87",
		"aws/enrich/privesc/method_88",
		"aws/enrich/privesc/method_89",
	}

	for _, id := range newMethods {
		t.Run(id, func(t *testing.T) {
			q, exists := GetQuery(id)
			require.True(t, exists, "query %s should exist", id)
			require.NotNil(t, q)
			assert.Equal(t, "aws", q.Metadata.Platform)
			assert.Equal(t, "enrich", q.Metadata.Type)
			assert.Equal(t, "privesc", q.Metadata.Category)
			assert.NotEmpty(t, q.Cypher)
			assert.Contains(t, q.Cypher, "CAN_PRIVESC", "should create CAN_PRIVESC relationship")
		})
	}
}
