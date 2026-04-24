//go:build integration

package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
)

// Provider identifies a cloud provider for fixture configuration.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

// Config holds the parameters needed to set up a Terraform fixture.
type Config struct {
	Provider    Provider
	ModuleDir   string
	FixtureDir  string
	ExecPath    string
	ContainerID string
	StateKey    string
	StateURI    string
	ArtifactsURI string
	InitOpts    []tfexec.InitOption
}

// Fixture is the public interface for integration test fixtures.
type Fixture interface {
	Setup()
	Output(string) string
	OutputList(string) []string
}

// ops abstracts the operations that a fixture lifecycle depends on,
// enabling mock-based testing of the lifecycle state machine.
type ops interface {
	GetRemoteHash(context.Context) (string, error)
	PutRemoteHash(context.Context, string) error
	Init(context.Context, ...tfexec.InitOption) error
	Destroy(context.Context, ...tfexec.DestroyOption) error
	Apply(context.Context, ...tfexec.ApplyOption) error
	Output(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error)
	UploadArtifacts(context.Context) error
	DeleteArtifacts(context.Context) error
	PurgeModulePrefix(context.Context) error
}

// BaseFixture manages a Terraform fixture backed by S3 remote state.
type BaseFixture struct {
	tf       *tfexec.Terraform
	outputs  map[string]tfexec.OutputMeta
	t        *testing.T
	cfg      Config
	ops      ops
	registry *registry
}

type baseOps struct {
	fixture *BaseFixture
}

// NewBase creates a BaseFixture from the given config.
func NewBase(t *testing.T, cfg Config) *BaseFixture {
	t.Helper()

	cfg = initializeStorageConfig(cfg)

	tf, err := tfexec.NewTerraform(cfg.FixtureDir, cfg.ExecPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", cfg.ModuleDir, err)
	}

	fixture := &BaseFixture{tf: tf, t: t, cfg: cfg, registry: globalRegistry}
	fixture.ops = baseOps{fixture: fixture}

	return fixture
}

func initializeStorageConfig(cfg Config) Config {
	if cfg.StateURI == "" {
		cfg.StateURI = fmt.Sprintf("s3://%s/%s", stateBucket, cfg.StateKey)
	}

	if cfg.ArtifactsURI == "" {
		artifactsPath := filepath.ToSlash(filepath.Dir(cfg.StateKey))
		cfg.ArtifactsURI = fmt.Sprintf("s3://%s/%s/artifacts/", stateBucket, artifactsPath)
	}

	if len(cfg.InitOpts) == 0 {
		cfg.InitOpts = []tfexec.InitOption{
			tfexec.BackendConfig("bucket=" + stateBucket),
			tfexec.BackendConfig("region=" + stateRegion),
			tfexec.BackendConfig("key=" + cfg.StateKey),
			tfexec.Reconfigure(true),
		}
	}

	return cfg
}

// --- baseOps delegates to the underlying BaseFixture / terraform ---

func (o baseOps) GetRemoteHash(ctx context.Context) (string, error) {
	return o.fixture.getRemoteHash(ctx)
}

func (o baseOps) PutRemoteHash(ctx context.Context, hash string) error {
	return o.fixture.putRemoteHash(ctx, hash)
}

func (o baseOps) Init(ctx context.Context, opts ...tfexec.InitOption) error {
	return o.fixture.tf.Init(ctx, opts...)
}

func (o baseOps) Destroy(ctx context.Context, opts ...tfexec.DestroyOption) error {
	return o.fixture.tf.Destroy(ctx, opts...)
}

func (o baseOps) Apply(ctx context.Context, opts ...tfexec.ApplyOption) error {
	return o.fixture.tf.Apply(ctx, opts...)
}

func (o baseOps) Output(ctx context.Context, opts ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
	return o.fixture.tf.Output(ctx, opts...)
}

func (o baseOps) UploadArtifacts(ctx context.Context) error {
	return o.fixture.uploadFixtureArtifacts(ctx)
}

func (o baseOps) DeleteArtifacts(ctx context.Context) error {
	return o.fixture.deleteFixtureArtifacts(ctx)
}

func (o baseOps) PurgeModulePrefix(ctx context.Context) error {
	return o.fixture.purgeModulePrefix(ctx)
}

// --- Public API ---

// Setup runs the full fixture lifecycle: hash check, init, apply/reuse.
func (f *BaseFixture) Setup() {
	f.t.Helper()

	err := f.runLifecycle(context.Background())
	if err != nil {
		f.t.Fatalf("fixture setup failed: %v", err)
	}
}

func (f *BaseFixture) runLifecycle(ctx context.Context) error {
	f.t.Logf("terraform fixture state location: %s", f.cfg.StateURI)
	f.t.Logf("terraform fixture artifacts location: %s", f.cfg.ArtifactsURI)

	fixtureHash, err := computeFixtureHash(f.cfg.FixtureDir)
	if err != nil {
		return fmt.Errorf("compute fixture hash: %w", err)
	}
	f.t.Logf("terraform fixture local hash: %s", fixtureHash)

	effectiveHash := computeEffectiveHash(fixtureHash, f.cfg.ContainerID)
	remoteHash, err := f.ops.GetRemoteHash(ctx)
	if err != nil {
		return fmt.Errorf("get remote hash: %w", err)
	}

	if err := f.ops.Init(ctx, f.cfg.InitOpts...); err != nil {
		return fmt.Errorf("terraform init: %w", err)
	}

	redeployFixtures := os.Getenv("AURELIAN_REDEPLOY_FIXTURES") == "1"
	switch {
	case redeployFixtures:
		f.t.Log("terraform fixture hash check: AURELIAN_REDEPLOY_FIXTURES=1")
		f.t.Log("terraform fixture decision: teardown + redeploy (forced)")
		if err := f.redeployStack(ctx, effectiveHash); err != nil {
			return err
		}
	case remoteHash == "":
		f.t.Log("terraform fixture hash check: remote hash empty")
		f.t.Log("terraform fixture decision: deploy")
		if err := f.deployStack(ctx, effectiveHash); err != nil {
			return err
		}
	case remoteHash == effectiveHash:
		f.t.Log("terraform fixture hash check: hashes match")
		f.t.Log("terraform fixture decision: reuse existing fixture")
	default:
		f.t.Logf("terraform fixture hash check: hashes differ (remote=%s local_effective=%s)", remoteHash, effectiveHash)
		f.t.Log("terraform fixture decision: re-apply (drift detected)")
		if err := f.deployStack(ctx, effectiveHash); err != nil {
			return err
		}
	}

	if err := f.loadOutputs(ctx); err != nil {
		return err
	}

	// registry is nil only for BaseFixture literals constructed directly
	// in tests; NewBase always sets it to globalRegistry for production use.
	if f.registry != nil {
		f.registry.register(f)
	}
	return nil
}

// Output returns a single Terraform output as a string.
func (f *BaseFixture) Output(key string) string {
	f.t.Helper()

	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}

	var s string
	err := json.Unmarshal(meta.Value, &s)
	if err != nil {
		f.t.Fatalf("terraform output %q is not a string: %s", key, string(meta.Value))
	}

	return s
}

// OutputList returns a Terraform output as a string slice.
func (f *BaseFixture) OutputList(key string) []string {
	f.t.Helper()

	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}

	var result []string
	err := json.Unmarshal(meta.Value, &result)
	if err != nil {
		f.t.Fatalf("terraform output %q is not a string list: %s", key, string(meta.Value))
	}

	return result
}
