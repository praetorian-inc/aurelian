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
	fixture, calls, _ := newLifecycleFixture(t, "", nil, nil)

	err := fixture.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "apply", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_RemoteHashMatch_ReusesWithoutApply(t *testing.T) {
	fixture, calls, effectiveHash := newLifecycleFixture(t, "", nil, nil)
	fixture.getRemoteHashFn = func(context.Context) (string, error) { return effectiveHash, nil }

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
	fixture, calls, effectiveHash := newLifecycleFixture(t, "", nil, nil)
	fixture.getRemoteHashFn = func(context.Context) (string, error) { return effectiveHash + "-stale", nil }

	err := fixture.runLifecycle(context.Background())
	if err != nil {
		t.Fatalf("run lifecycle: %v", err)
	}

	expected := []string{"init", "destroy", "apply", "put", "output"}
	if !slices.Equal(*calls, expected) {
		t.Fatalf("unexpected calls: got=%v want=%v", *calls, expected)
	}
}

func TestRunLifecycle_GetRemoteHashError_Fails(t *testing.T) {
	expectedErr := errors.New("hash read failed")
	fixture, _, _ := newLifecycleFixture(t, "", expectedErr, nil)

	err := fixture.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunLifecycle_OutputError_Fails(t *testing.T) {
	expectedErr := errors.New("output failed")
	fixture, _, _ := newLifecycleFixture(t, "", nil, expectedErr)

	err := fixture.runLifecycle(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func newLifecycleFixture(t *testing.T, remoteHash string, hashErr error, outputErr error) (*BaseFixture, *[]string, string) {
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
	fixture := &BaseFixture{t: t, cfg: fixtureConfig{fixtureDir: dir, containerID: "container", initOpts: []tfexec.InitOption{}}}
	fixture.getRemoteHashFn = func(context.Context) (string, error) {
		if hashErr != nil {
			return "", hashErr
		}
		return remoteHash, nil
	}
	fixture.putRemoteHashFn = func(context.Context, string) error {
		calls = append(calls, "put")
		return nil
	}
	fixture.initFn = func(context.Context, ...tfexec.InitOption) error {
		calls = append(calls, "init")
		return nil
	}
	fixture.destroyFn = func(context.Context, ...tfexec.DestroyOption) error {
		calls = append(calls, "destroy")
		return nil
	}
	fixture.applyFn = func(context.Context, ...tfexec.ApplyOption) error {
		calls = append(calls, "apply")
		return nil
	}
	fixture.outputFn = func(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
		calls = append(calls, "output")
		if outputErr != nil {
			return nil, outputErr
		}
		return map[string]tfexec.OutputMeta{}, nil
	}

	return fixture, &calls, effectiveHash
}

func createFixtureFiles(dir string) error {
	return os.WriteFile(dir+"/main.tf", []byte("resource {}"), 0o644)
}
