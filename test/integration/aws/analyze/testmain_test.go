//go:build integration

package analyze

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil"
)

// sharedNeo4jBoltURL holds the bolt URL for the shared Neo4j container.
// Tests that need Neo4j should use this instead of starting their own container.
// It is empty if the container failed to start.
var sharedNeo4jBoltURL string

func TestMain(m *testing.M) {
	ctx := context.Background()

	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start shared Neo4j container: %v\n", err)
		os.Exit(1)
	}
	sharedNeo4jBoltURL = boltURL

	// Run all tests
	code := m.Run()

	// Cleanup
	cleanup()
	os.Exit(code)
}
