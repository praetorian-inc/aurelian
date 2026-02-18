package plugin

import (
	"context"
	"testing"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGraphDB implements graph.GraphDatabase for testing
type mockGraphDB struct {
	nodesCreated         []*graph.Node
	relationshipsCreated []*graph.Relationship
	queries              []string
	queryResults         *graph.QueryResult
	queryError           error
	verifyError          error
}

func (m *mockGraphDB) CreateNodes(ctx context.Context, nodes []*graph.Node) (*graph.BatchResult, error) {
	m.nodesCreated = append(m.nodesCreated, nodes...)
	return &graph.BatchResult{
		NodesCreated:    len(nodes),
		ExecutionTimeMs: 100,
	}, nil
}

func (m *mockGraphDB) CreateRelationships(ctx context.Context, rels []*graph.Relationship) (*graph.BatchResult, error) {
	m.relationshipsCreated = append(m.relationshipsCreated, rels...)
	return &graph.BatchResult{
		RelationshipsCreated: len(rels),
		ExecutionTimeMs:      50,
	}, nil
}

func (m *mockGraphDB) Query(ctx context.Context, cypher string, params map[string]any) (*graph.QueryResult, error) {
	m.queries = append(m.queries, cypher)
	if m.queryError != nil {
		return nil, m.queryError
	}
	// Return default result if none set
	if m.queryResults == nil {
		return &graph.QueryResult{
			Records: []map[string]interface{}{},
			Summary: graph.QuerySummary{
				NodesCreated:         0,
				RelationshipsCreated: 0,
				PropertiesSet:        0,
			},
		}, nil
	}
	return m.queryResults, nil
}

func (m *mockGraphDB) VerifyConnectivity(ctx context.Context) error {
	return m.verifyError
}

func (m *mockGraphDB) Close() error {
	return nil
}

// TestGraphFormatterImplementsFormatter verifies GraphFormatter satisfies the Formatter interface
func TestGraphFormatterImplementsFormatter(t *testing.T) {
	mockDB := &mockGraphDB{}
	formatter := &GraphFormatter{db: mockDB}

	// This will compile only if GraphFormatter implements Formatter
	var _ Formatter = formatter
}

// TestGraphFormatterFormatWithGaadData tests the full format flow with all data types
func TestGraphFormatterFormatWithGaadData(t *testing.T) {
	mockDB := &mockGraphDB{}
	formatter := &GraphFormatter{db: mockDB, config: &graph.Config{URI: "bolt://localhost:7687"}}

	// Create test data as AWSIAMResource entities
	userEntity := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			Platform: "aws", ResourceType: "AWS::IAM::User",
			ResourceID: "arn:aws:iam::123456789012:user/testuser",
			ARN: "arn:aws:iam::123456789012:user/testuser",
			AccountRef: "123456789012", DisplayName: "testuser",
		},
	}
	roleEntity := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			Platform: "aws", ResourceType: "AWS::IAM::Role",
			ResourceID: "arn:aws:iam::123456789012:role/testrole",
			ARN: "arn:aws:iam::123456789012:role/testrole",
			AccountRef: "123456789012", DisplayName: "testrole",
		},
	}
	groupEntity := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			Platform: "aws", ResourceType: "AWS::IAM::Group",
			ResourceID: "arn:aws:iam::123456789012:group/testgroup",
			ARN: "arn:aws:iam::123456789012:group/testgroup",
			AccountRef: "123456789012", DisplayName: "testgroup",
		},
	}
	bucketEntity := output.FromAWSResource(output.AWSResource{
		ARN: "arn:aws:s3:::mybucket", ResourceType: "AWS::S3::Bucket",
		Properties: map[string]any{"Name": "mybucket"},
	})

	entities := []output.AWSIAMResource{userEntity, roleEntity, groupEntity, bucketEntity}

	user := iampkg.UserDL{Arn: "arn:aws:iam::123456789012:user/testuser", UserName: "testuser", UserId: "AIDAI123456"}
	fullResults := []iampkg.FullResult{
		{
			Principal: &user,
			Action:    "s3:GetObject",
		},
	}

	results := []Result{
		{Data: entities, Metadata: map[string]any{"type": "entities"}},
		{Data: fullResults, Metadata: map[string]any{"type": "iam_relationships"}},
	}

	err := formatter.Format(results)
	require.NoError(t, err)

	// Verify nodes were created
	assert.Equal(t, 4, len(mockDB.nodesCreated), "Expected 4 nodes (1 user, 1 role, 1 group, 1 resource)")

	// Verify relationships were created
	assert.Equal(t, 1, len(mockDB.relationshipsCreated), "Expected 1 relationship")

	// Verify enrichment queries were run
	assert.Greater(t, len(mockDB.queries), 0, "Expected enrichment queries to be run")
}

// TestGraphFormatterFormatNoGaadError tests error when no GAAD data is present
func TestGraphFormatterFormatNoGaadError(t *testing.T) {
	mockDB := &mockGraphDB{}
	formatter := &GraphFormatter{db: mockDB}

	// Results without entity data
	results := []Result{
		{Data: []iampkg.FullResult{}, Metadata: map[string]any{"type": "iam_relationships"}},
	}

	err := formatter.Format(results)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no entity data found")
}

// TestGraphFormatterFormatFlattenMap tests flattening map[string][]AWSResource
func TestGraphFormatterFormatFlattenMap(t *testing.T) {
	mockDB := &mockGraphDB{}
	formatter := &GraphFormatter{db: mockDB, config: &graph.Config{URI: "bolt://localhost:7687"}}

	entities := []output.AWSIAMResource{
		{AWSResource: output.AWSResource{
			Platform: "aws", ResourceType: "AWS::IAM::User",
			ResourceID: "arn:aws:iam::123456789012:user/testuser",
			ARN: "arn:aws:iam::123456789012:user/testuser",
			AccountRef: "123456789012", DisplayName: "testuser",
		}},
		output.FromAWSResource(output.AWSResource{
			ARN: "arn:aws:s3:::bucket1", ResourceType: "AWS::S3::Bucket",
		}),
		output.FromAWSResource(output.AWSResource{
			ARN: "arn:aws:s3:::bucket2", ResourceType: "AWS::S3::Bucket",
		}),
	}

	results := []Result{
		{Data: entities, Metadata: map[string]any{"type": "entities"}},
		{Data: []iampkg.FullResult{}, Metadata: map[string]any{"type": "iam_relationships"}},
	}

	err := formatter.Format(results)
	require.NoError(t, err)

	// Verify all entities were created as nodes
	// 1 user + 2 resources = 3 nodes
	assert.Equal(t, 3, len(mockDB.nodesCreated), "Expected 3 nodes")
}
