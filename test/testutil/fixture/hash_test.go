package fixture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeFixtureHash_DeterministicAndContentSensitive(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "outputs.tf"), []byte("output {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	h1, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}

	// Change content → hash changes
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {v2}"), 0o644); err != nil {
		t.Fatal(err)
	}
	h3, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("hash should change when file content changes")
	}
}

func TestComputeFixtureHash_ExcludesTerraformDirs(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	h1, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Add .terraform/ dir and .terraform.lock.hcl — hash should not change
	terraDir := filepath.Join(dir, ".terraform")
	if err := os.MkdirAll(terraDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(terraDir, "plugin.bin"), []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte("lock"), 0o644); err != nil {
		t.Fatal(err)
	}

	h2, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash should ignore .terraform/ and .terraform.lock.hcl: %s != %s", h1, h2)
	}
}

func TestComputeFixtureHash_FileAdditionChangesHash(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	h1, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "lambda.zip"), []byte("zipdata"), 0o644); err != nil {
		t.Fatal(err)
	}

	h2, err := computeFixtureHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("hash should change when a file is added")
	}
}

func TestComputeEffectiveHash_IncludesContainerID(t *testing.T) {
	fixtureHash := "abc123"
	aws1 := computeEffectiveHash(fixtureHash, "111111111111")
	aws2 := computeEffectiveHash(fixtureHash, "222222222222")

	if aws1 == aws2 {
		t.Fatal("effective hash must differ across container IDs")
	}
}
