package escalation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeModelFile(t *testing.T, dir string, name string, m *Model) string {
	t.Helper()
	data, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

func TestLoadAndMergeModelFiles_TwoFiles(t *testing.T) {
	dir := t.TempDir()

	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/RoleA", Account: "111111111111", Type: PrincipalTypeRole},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::111111111111:role/RoleA", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::222222222222:role/RoleB"},
			}},
		},
		nil,
	)

	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/RoleB", Account: "222222222222", Type: PrincipalTypeRole, IsAdmin: true},
		},
		[]PolicySummaryEntry{
			{Principal: "arn:aws:iam::222222222222:role/RoleB", EffectiveStatements: []PolicyStatement{
				{Effect: "Allow", Action: "*", Resource: "*"},
			}},
		},
		[]StructuralFact{
			{Type: FactTrustRelationship, From: "arn:aws:iam::222222222222:role/RoleB", To: "arn:aws:iam::111111111111:root", Confidence: 1.0},
		},
	)

	pathA := writeModelFile(t, dir, "account-111.model.json", modelA)
	pathB := writeModelFile(t, dir, "account-222.model.json", modelB)

	merged, err := LoadAndMergeModelFiles([]string{pathA, pathB})
	require.NoError(t, err)

	assert.Len(t, merged.Accounts, 2)
	assert.Len(t, merged.Principals, 2)
	assert.Len(t, merged.PermissionSource.Entries, 2)

	// Root trust should be expanded
	found := false
	for _, f := range merged.StructuralFacts {
		if f.Type == FactTrustRelationship &&
			f.From == "arn:aws:iam::222222222222:role/RoleB" &&
			f.To == "arn:aws:iam::111111111111:role/RoleA" {
			found = true
		}
	}
	assert.True(t, found, "root trust should be expanded to RoleA")
}

func TestLoadAndMergeModelFiles_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(badPath, []byte("not json"), 0644))

	_, err := LoadAndMergeModelFiles([]string{badPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.json")
}

func TestLoadAndMergeModelFiles_MissingFile(t *testing.T) {
	_, err := LoadAndMergeModelFiles([]string{"/nonexistent/path.json"})
	require.Error(t, err)
}

func TestLoadAndMergeModelFiles_EmptyPaths(t *testing.T) {
	_, err := LoadAndMergeModelFiles(nil)
	require.Error(t, err)
}

func TestLoadAndMergeModelFiles_GlobDir(t *testing.T) {
	dir := t.TempDir()

	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
		}, nil, nil,
	)
	modelB := accountModel("222222222222",
		[]Principal{
			{ARN: "arn:aws:iam::222222222222:role/R", Account: "222222222222", Type: PrincipalTypeRole},
		}, nil, nil,
	)

	writeModelFile(t, dir, "a.json", modelA)
	writeModelFile(t, dir, "b.json", modelB)
	// non-json file should be ignored by GlobModelFiles
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0644))

	paths, err := GlobModelFiles(dir)
	require.NoError(t, err)
	assert.Len(t, paths, 2)

	merged, err := LoadAndMergeModelFiles(paths)
	require.NoError(t, err)
	assert.Len(t, merged.Accounts, 2)
}

func TestGlobModelFiles_ExcludesPath(t *testing.T) {
	dir := t.TempDir()

	modelA := accountModel("111111111111",
		[]Principal{
			{ARN: "arn:aws:iam::111111111111:role/R", Account: "111111111111", Type: PrincipalTypeRole},
		}, nil, nil,
	)
	writeModelFile(t, dir, "a.json", modelA)
	writeModelFile(t, dir, "merged.json", modelA)

	paths, err := GlobModelFiles(dir, filepath.Join(dir, "merged.json"))
	require.NoError(t, err)
	assert.Len(t, paths, 1)
	assert.Contains(t, paths[0], "a.json")
}

func TestMergeStats(t *testing.T) {
	m := &Model{
		Accounts: []Account{{ID: "111"}, {ID: "222"}},
		Principals: []Principal{
			{ARN: "a"}, {ARN: "b"}, {ARN: "c"},
		},
		Resources: []Resource{
			{ARN: "r1"}, {ARN: "r2"},
		},
		StructuralFacts: []StructuralFact{
			{Type: FactTrustRelationship},
		},
	}

	stats := MergeStats(m)
	assert.Equal(t, 2, stats.Accounts)
	assert.Equal(t, 3, stats.Principals)
	assert.Equal(t, 2, stats.Resources)
	assert.Equal(t, 1, stats.StructuralFacts)
}
