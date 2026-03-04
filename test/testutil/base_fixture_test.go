//go:build integration

package testutil

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
)

func TestConstructorSymbolsExist(t *testing.T) {
	_ = NewAWSFixture
	_ = NewAzureFixture
}

func TestComputeEffectiveHash_IncludesContainerID(t *testing.T) {
	fixtureHash := "abc123"
	aws1 := computeEffectiveHash(fixtureHash, "111111111111")
	aws2 := computeEffectiveHash(fixtureHash, "222222222222")

	if aws1 == aws2 {
		t.Fatal("effective hash must differ across container IDs")
	}
}

func TestRunLifecycle_RemoteHashMissing_AppliesAndStoresHash(t *testing.T) {
	fixture, calls, _, _ := newLifecycleFixture(t, "", nil, nil)

	err := fixture.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "apply", "upload", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_RemoteHashMatch_ReusesWithoutApply(t *testing.T) {
	fixture, calls, effectiveHash, ops := newLifecycleFixture(t, "", nil, nil)
	ops.remoteHash = effectiveHash

	err := fixture.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_RemoteHashMismatch_DestroysThenApplies(t *testing.T) {
	fixture, calls, effectiveHash, ops := newLifecycleFixture(t, "", nil, nil)
	ops.remoteHash = effectiveHash + "-stale"

	err := fixture.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "destroy", "delete", "apply", "upload", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_GetRemoteHashError_Fails(t *testing.T) {
	expectedErr := errors.New("hash read failed")
	fixture, _, _, _ := newLifecycleFixture(t, "", expectedErr, nil)

	err := fixture.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunLifecycle_OutputError_Fails(t *testing.T) {
	expectedErr := errors.New("output failed")
	fixture, _, _, _ := newLifecycleFixture(t, "", nil, expectedErr)

	err := fixture.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

type mockFixtureOps struct {
	calls     *[]string
	remoteHash string
	hashErr   error
	outputErr error
}

func (m *mockFixtureOps) GetRemoteHash(context.Context) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return m.remoteHash, nil
}

func (m *mockFixtureOps) PutRemoteHash(context.Context, string) error {
	*m.calls = append(*m.calls, "put")
	return nil
}

func (m *mockFixtureOps) Init(context.Context, ...tfexec.InitOption) error {
	*m.calls = append(*m.calls, "init")
	return nil
}

func (m *mockFixtureOps) Destroy(context.Context, ...tfexec.DestroyOption) error {
	*m.calls = append(*m.calls, "destroy")
	return nil
}

func (m *mockFixtureOps) Apply(context.Context, ...tfexec.ApplyOption) error {
	*m.calls = append(*m.calls, "apply")
	return nil
}

func (m *mockFixtureOps) Output(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
	*m.calls = append(*m.calls, "output")
	if m.outputErr != nil {
		return nil, m.outputErr
	}
	return map[string]tfexec.OutputMeta{}, nil
}

func (m *mockFixtureOps) UploadArtifacts(context.Context) error {
	*m.calls = append(*m.calls, "upload")
	return nil
}

func (m *mockFixtureOps) DeleteArtifacts(context.Context) error {
	*m.calls = append(*m.calls, "delete")
	return nil
}

func newLifecycleFixture(t *testing.T, remoteHash string, hashErr error, outputErr error) (*BaseFixture, *[]string, string, *mockFixtureOps) {
	t.Helper()

	dir := t.TempDir()
	if err := createFixtureFiles(dir); err != nil {
		t.Fatalf("create fixture files: %v", err)
	}

	fixtureHash, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatalf("compute fixture hash: %v", err)
	}
	effectiveHash := computeEffectiveHash(fixtureHash, "container")

	calls := []string{}
	ops := &mockFixtureOps{calls: &calls, remoteHash: remoteHash, hashErr: hashErr, outputErr: outputErr}
	fixture := &BaseFixture{
		t: t,
		cfg: fixtureConfig{fixtureDir: dir, containerID: "container", stateURI: "test://state", artifactsURI: "test://artifacts/", initOpts: []tfexec.InitOption{}},
		ops: ops,
	}

	return fixture, &calls, effectiveHash, ops
}

func createFixtureFiles(dir string) error {
	return os.WriteFile(dir+"/main.tf", []byte("resource {}"), 0o644)
}
