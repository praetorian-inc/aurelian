//go:build integration

package fixture

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestDestroyAll_RemovesModulePrefix(t *testing.T) {
	// Use a private registry so this test does not interact with other tests
	// in the package (which use the global registry indirectly via TestMain).
	reg := &registry{}

	f := newCanaryFixture(t)
	f.registry = reg
	f.Setup()

	ctx := context.Background()

	// Sanity: state + artifacts + hash all exist under the prefix.
	assertPrefixPopulated(t, ctx, f.cfg.StateKey)

	if err := reg.DestroyAll(ctx); err != nil {
		t.Fatalf("DestroyAll: %v", err)
	}

	assertPrefixEmpty(t, ctx, f.cfg.StateKey)
}

func TestDestroyAll_KeepFlag_DoesNotInvoke(t *testing.T) {
	// Independent of Setup — just verifies the RunTests gate calls destroyFn
	// iff the env var isn't set. This is already covered by unit tests, but
	// we re-exercise under the integration tag to catch env-read regressions.
	t.Setenv("AURELIAN_KEEP_FIXTURES", "1")
	called := false
	code := runTestsWith(stubM{code: 0}, func(context.Context) error {
		called = true
		return nil
	}, os.Getenv)

	if code != 0 || called {
		t.Fatalf("KEEP_FIXTURES=1 should skip destroy: code=%d called=%v", code, called)
	}
}

// --- helpers ---

func newCanaryFixture(t *testing.T) *BaseFixture {
	t.Helper()

	execPath, err := lookTerraform()
	if err != nil {
		t.Fatalf("terraform not found: %v", err)
	}

	EnsureStateBucket(t)
	accountID, err := ResolveAWSAccountID(context.Background())
	if err != nil {
		t.Fatalf("resolve account id: %v", err)
	}

	return NewBase(t, Config{
		Provider:    ProviderAWS,
		ModuleDir:   "test/destroy-canary",
		FixtureDir:  locateFixtureDir(t, "test/destroy-canary"),
		ExecPath:    execPath,
		ContainerID: accountID,
		StateKey:    "integration-tests/test/destroy-canary/terraform.tfstate",
	})
}

func assertPrefixPopulated(t *testing.T, ctx context.Context, stateKey string) {
	t.Helper()
	keys := listModulePrefix(t, ctx, stateKey)
	if len(keys) == 0 {
		t.Fatalf("expected objects under module prefix, got none")
	}
}

func assertPrefixEmpty(t *testing.T, ctx context.Context, stateKey string) {
	t.Helper()
	keys := listModulePrefix(t, ctx, stateKey)
	if len(keys) != 0 {
		t.Fatalf("expected module prefix to be empty, got %v", keys)
	}
}

func listModulePrefix(t *testing.T, ctx context.Context, stateKey string) []string {
	t.Helper()
	client, err := newS3Client(ctx)
	if err != nil {
		t.Fatalf("s3 client: %v", err)
	}
	prefix := stateKey[:len(stateKey)-len("terraform.tfstate")]

	var keys []string
	var token *string
	for {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &stateBucket,
			Prefix:            &prefix,
			ContinuationToken: token,
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, o := range out.Contents {
			if o.Key != nil {
				keys = append(keys, *o.Key)
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return keys
		}
		token = out.NextContinuationToken
	}
}
