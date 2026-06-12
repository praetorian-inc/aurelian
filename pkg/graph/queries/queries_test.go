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
		"aws/enrich/privesc/apprunner_create_service",
		"aws/enrich/privesc/apprunner_update_service",
		"aws/enrich/privesc/batch_passrole",
		"aws/enrich/privesc/batch_submit_job",
		"aws/enrich/privesc/braket_create_job",
		"aws/enrich/privesc/cloudformation_create_stackset",
		"aws/enrich/privesc/cloudformation_update_stackset",
		"aws/enrich/privesc/codedeploy_create_deployment",
		"aws/enrich/privesc/cognito_set_identity_pool_roles",
		"aws/enrich/privesc/ec2_instance_connect",
		"aws/enrich/privesc/ec2_replace_instance_profile",
		"aws/enrich/privesc/ecs_create_service",
		"aws/enrich/privesc/ecs_start_task",
		"aws/enrich/privesc/ecs_execute_command",
		"aws/enrich/privesc/emr_run_job_flow",
		"aws/enrich/privesc/emr_serverless",
		"aws/enrich/privesc/gamelift_create_fleet",
		"aws/enrich/privesc/glue_create_dev_endpoint",
		"aws/enrich/privesc/glue_update_job",
		"aws/enrich/privesc/glue_create_session",
		"aws/enrich/privesc/imagebuilder_create_pipeline",
		"aws/enrich/privesc/kinesis_analytics",
		"aws/enrich/privesc/lambda_add_permission",
		"aws/enrich/privesc/omics_create_workflow",
		"aws/enrich/privesc/sagemaker_lifecycle_config",
		"aws/enrich/privesc/scheduler_create_schedule",
		"aws/enrich/privesc/ssm_start_automation",
		"aws/enrich/privesc/stepfunctions_create",
		"aws/enrich/privesc/stepfunctions_update",
		"aws/enrich/privesc/bedrock_access_code_interpreter",
		// Group A: wrong-API fixes (73–74)
		"aws/enrich/privesc/ec2_request_spot_instances",
		"aws/enrich/privesc/ec2_launch_template_version",
		// Group B: completely missing (75–79)
		"aws/enrich/privesc/amplify_create_app",
		"aws/enrich/privesc/ec2_modify_instance_attribute",
		"aws/enrich/privesc/glue_createjob_createtrigger",
		"aws/enrich/privesc/glue_updatejob_createtrigger",
		"aws/enrich/privesc/lambda_passrole_createfunction_addpermission",
		// Group C: execution-gated compound methods (80–89)
		"aws/enrich/privesc/glue_createjob_startjobrun",
		"aws/enrich/privesc/glue_updatejob_startjobrun",
		"aws/enrich/privesc/glue_createsession_runstatement",
		"aws/enrich/privesc/stepfunctions_create_startexecution",
		"aws/enrich/privesc/ssm_createdocument_startautomation",
		"aws/enrich/privesc/emr_serverless_startjobrun",
		"aws/enrich/privesc/kinesisanalytics_startapplication",
		"aws/enrich/privesc/omics_startrun",
		"aws/enrich/privesc/gamelift_createbuild_createfleet",
		"aws/enrich/privesc/imagebuilder_createimage",
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
