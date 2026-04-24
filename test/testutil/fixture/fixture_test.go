//go:build integration

package fixture

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
)

func TestRunLifecycle_RemoteHashMissing_AppliesAndStoresHash(t *testing.T) {
	f, calls, _, _ := newLifecycleFixture(t, "", nil, nil)

	err := f.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "apply", "upload", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_RemoteHashMatch_ReusesWithoutApply(t *testing.T) {
	f, calls, effectiveHash, mock := newLifecycleFixture(t, "", nil, nil)
	mock.remoteHash = effectiveHash

	err := f.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_RemoteHashMismatch_ReApplies(t *testing.T) {
	f, calls, effectiveHash, mock := newLifecycleFixture(t, "", nil, nil)
	mock.remoteHash = effectiveHash + "-stale"

	err := f.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "apply", "upload", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_GetRemoteHashError_Fails(t *testing.T) {
	expectedErr := errors.New("hash read failed")
	f, _, _, _ := newLifecycleFixture(t, "", expectedErr, nil)

	err := f.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunLifecycle_OutputError_Fails(t *testing.T) {
	expectedErr := errors.New("output failed")
	f, _, _, _ := newLifecycleFixture(t, "", nil, expectedErr)

	err := f.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

type mockOps struct {
	calls      *[]string
	remoteHash string
	hashErr    error
	outputErr  error
}

func (m *mockOps) GetRemoteHash(context.Context) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return m.remoteHash, nil
}

func (m *mockOps) PutRemoteHash(context.Context, string) error {
	*m.calls = append(*m.calls, "put")
	return nil
}

func (m *mockOps) Init(context.Context, ...tfexec.InitOption) error {
	*m.calls = append(*m.calls, "init")
	return nil
}

func (m *mockOps) Destroy(context.Context, ...tfexec.DestroyOption) error {
	*m.calls = append(*m.calls, "destroy")
	return nil
}

func (m *mockOps) Apply(context.Context, ...tfexec.ApplyOption) error {
	*m.calls = append(*m.calls, "apply")
	return nil
}

func (m *mockOps) Output(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
	*m.calls = append(*m.calls, "output")
	if m.outputErr != nil {
		return nil, m.outputErr
	}
	return map[string]tfexec.OutputMeta{}, nil
}

func (m *mockOps) UploadArtifacts(context.Context) error {
	*m.calls = append(*m.calls, "upload")
	return nil
}

func (m *mockOps) DeleteArtifacts(context.Context) error {
	*m.calls = append(*m.calls, "delete")
	return nil
}

func TestRunLifecycle_RedeployEnvVar_ForcesRedeploy(t *testing.T) {
	t.Setenv("AURELIAN_REDEPLOY_FIXTURES", "1")

	f, calls, effectiveHash, mock := newLifecycleFixture(t, "", nil, nil)
	mock.remoteHash = effectiveHash // hash matches, but the env var should force redeploy

	err := f.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	// downloadArtifactsToTempDir fails (no artifacts in S3 under the test prefix)
	// so redeployStack falls back to ops.Destroy, then re-init + apply.
	expected := []string{"init", "destroy", "delete", "init", "apply", "upload", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func newLifecycleFixture(t *testing.T, remoteHash string, hashErr error, outputErr error) (*BaseFixture, *[]string, string, *mockOps) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/main.tf", []byte("resource {}"), 0o644); err != nil {
		t.Fatalf("create fixture files: %v", err)
	}

	fixtureHash, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatalf("compute fixture hash: %v", err)
	}
	effectiveHash := computeEffectiveHash(fixtureHash, "container")

	calls := []string{}
	mock := &mockOps{calls: &calls, remoteHash: remoteHash, hashErr: hashErr, outputErr: outputErr}
	f := &BaseFixture{
		t: t,
		cfg: Config{
			FixtureDir:   dir,
			ContainerID:  "container",
			StateURI:     "test://state",
			ArtifactsURI: "test://artifacts/",
			InitOpts:     []tfexec.InitOption{},
		},
		ops: mock,
	}

	return f, &calls, effectiveHash, mock
}
