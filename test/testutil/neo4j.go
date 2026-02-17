//go:build integration

package testutil

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	neo4jcontainer "github.com/testcontainers/testcontainers-go/modules/neo4j"
)

// StartNeo4jContainer starts a shared Neo4j 5.x container and returns the bolt URL
// and a cleanup function. The caller is responsible for calling cleanup when done.
func StartNeo4jContainer(ctx context.Context) (boltURL string, cleanup func(), err error) {
	container, err := neo4jcontainer.Run(ctx, "neo4j:5",
		neo4jcontainer.WithoutAuthentication(),
	)
	if err != nil {
		return "", nil, err
	}

	boltURL, err = container.BoltUrl(ctx)
	if err != nil {
		container.Terminate(ctx)
		return "", nil, err
	}

	cleanup = func() {
		container.Terminate(ctx)
	}

	return boltURL, cleanup, nil
}

// ClearNeo4jDatabase deletes all nodes and relationships for test isolation.
func ClearNeo4jDatabase(t *testing.T, boltURL string) {
	t.Helper()
	cfg := graph.NewConfig(boltURL, "", "")
	adapter, err := adapters.NewNeo4jAdapter(cfg)
	if err != nil {
		t.Fatalf("failed to create adapter for cleanup: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.Query(context.Background(), "MATCH (n) DETACH DELETE n", nil)
	if err != nil {
		t.Fatalf("failed to clear database: %v", err)
	}
}
