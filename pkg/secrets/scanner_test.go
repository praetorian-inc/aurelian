package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startScanner is a test helper that creates a SecretScanner with an isolated temp DB.
func startScanner(t *testing.T) *SecretScanner {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "titus.db")
	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath}))
	t.Cleanup(func() { _ = s.Close() })
	return &s
}

// ---------------------------------------------------------------------------
// SecretScanner API tests
// ---------------------------------------------------------------------------

func TestSecretScanner_StartAndClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath}))

	assert.Equal(t, dbPath, s.DBPath())
	_, err := os.Stat(dbPath)
	assert.NoError(t, err, "database file should exist")

	require.NoError(t, s.Close())
	assert.Empty(t, s.DBPath(), "DBPath should be empty after close")
}

func TestSecretScanner_CloseWithoutStart(t *testing.T) {
	var s SecretScanner
	assert.NoError(t, s.Close())
}

func TestSecretScanner_DBPathBeforeStart(t *testing.T) {
	var s SecretScanner
	assert.Empty(t, s.DBPath(), "DBPath should be empty before start")
}

func TestSecretScanner_ScanPipelineNoSecrets(t *testing.T) {
	s := startScanner(t)

	input := output.ScanInput{
		Content:      []byte("just some regular text"),
		ResourceID:   "arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
		ResourceType: "AWS::EC2::Instance",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Label:        "readme.txt",
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(input, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestToScanResult_CarriesFullMatch(t *testing.T) {
	match := &types.Match{
		RuleID:    "np.aws.1",
		RuleName:  "AWS API Key",
		Snippet: types.Snippet{
			Before:   []byte("before"),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("after"),
		},
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 30},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 5, Column: 1},
				End:   types.SourcePoint{Line: 5, Column: 21},
			},
		},
	}

	input := output.ScanInput{
		ResourceID: "arn:aws:lambda:us-east-1:123456789012:function:demo",
		Label:      "main.py",
	}

	result := toScanResult(input, match)

	assert.Equal(t, input.ResourceID, result.ResourceRef)
	assert.Equal(t, "main.py", result.Label)
	assert.Same(t, match, result.Match, "Match should be the original *types.Match pointer")
}

// ---------------------------------------------------------------------------
// Persistent scanner creation tests (ported from pkg/scanner/titus_test.go)
// ---------------------------------------------------------------------------

func TestStart_ExplicitPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath}))
	defer func() { _ = s.Close() }()

	assert.Equal(t, dbPath, s.DBPath(), "DBPath should return the provided path")
	_, err := os.Stat(dbPath)
	assert.NoError(t, err, "database file should exist at provided path")
}

func TestStart_CustomPath(t *testing.T) {
	customPath := filepath.Join(t.TempDir(), "custom-titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: customPath}))
	defer s.Close()

	assert.Equal(t, customPath, s.DBPath(), "DBPath should return custom path")
	_, err := os.Stat(customPath)
	assert.NoError(t, err, "database file should exist at custom path")
}

func TestStart_CreatesParentDirectories(t *testing.T) {
	customPath := filepath.Join(t.TempDir(), "deeply", "nested", "path", "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: customPath}))
	defer s.Close()

	_, err := os.Stat(filepath.Dir(customPath))
	assert.NoError(t, err, "parent directories should exist")
	_, err = os.Stat(customPath)
	assert.NoError(t, err, "database file should exist")
}

func TestStart_OutputDirectoryCreated(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "output", "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath}))
	defer s.Close()

	_, err := os.Stat(filepath.Join(tmpDir, "output"))
	require.NoError(t, err, "output directory should exist")

	assert.Equal(t, dbPath, s.DBPath(), "database should be at the provided path")
}

// ---------------------------------------------------------------------------
// Content scanning tests (ported from pkg/scanner/titus_test.go)
// ---------------------------------------------------------------------------

func TestScanContent(t *testing.T) {
	// Pre-existing failure: Titus FK constraint error when storing matches for this content.
	// See: "failed to store match: constraint failed: FOREIGN KEY constraint failed (787)"

	s := startScanner(t)

	content := []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test/credentials.txt"}

	// First scan — should detect and store
	matches, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent should succeed")
	assert.NotNil(t, matches, "matches should not be nil")

	// Second scan — should return cached results (incremental scanning)
	cachedMatches, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent should succeed on second scan")
	assert.NotNil(t, cachedMatches, "cached matches should not be nil")
	assert.Equal(t, len(matches), len(cachedMatches), "cached matches should have same count")
}

func TestIncrementalScanning(t *testing.T) {
	s := startScanner(t)

	content1 := []byte("some content here")
	blobID1 := types.ComputeBlobID(content1)
	provenance1 := types.FileProvenance{FilePath: "file1.txt"}

	content2 := []byte("different content")
	blobID2 := types.ComputeBlobID(content2)
	provenance2 := types.FileProvenance{FilePath: "file2.txt"}

	// Scan first blob
	_, err := s.ps.scanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "first scan should succeed")

	// Scan second blob
	_, err = s.ps.scanContent(content2, blobID2, provenance2)
	require.NoError(t, err, "second scan should succeed")

	// Re-scan first blob (should skip scanning)
	_, err = s.ps.scanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "re-scan should succeed")
}

func TestDatabasePersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")

	content := []byte("test content")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test.txt"}

	// Create scanner and scan content
	var s1 SecretScanner
	require.NoError(t, s1.Start(ScannerConfig{DBPath: dbPath}))

	initialMatches, err := s1.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent should succeed")

	// Close first scanner
	require.NoError(t, s1.Close())

	// Verify database file still exists
	_, err = os.Stat(dbPath)
	require.NoError(t, err, "database file should persist after close")

	// Create new scanner with same database
	var s2 SecretScanner
	require.NoError(t, s2.Start(ScannerConfig{DBPath: dbPath}))
	defer s2.Close()

	// Scan same content — should find it already exists
	cachedMatches, err := s2.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent with existing blob should succeed")
	assert.Equal(t, len(initialMatches), len(cachedMatches), "cached matches should have same count as initial scan")
}

func TestClose(t *testing.T) {
	s := startScanner(t)

	// Close should succeed
	err := s.Close()
	assert.NoError(t, err, "Close should succeed")

	// Second close should not panic
	err = s.Close()
	assert.NoError(t, err, "second Close should not panic")
}

func TestScanContent_FindingID_PopulatedOnCachedPath(t *testing.T) {
	s := startScanner(t)

	content := []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test/credentials.txt"}

	// First scan — fresh match
	firstMatches, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)
	require.NotEmpty(t, firstMatches)
	for _, match := range firstMatches {
		assert.NotEmpty(t, match.FindingID, "FindingID should be populated on first scan")
	}

	// Second scan — hits cached path (store.GetMatches + populateFindingIDs)
	cachedMatches, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err)
	require.NotEmpty(t, cachedMatches)
	for i, match := range cachedMatches {
		assert.NotEmpty(t, match.FindingID, "FindingID should be populated on cached path")
		if i < len(firstMatches) {
			assert.Equal(t, firstMatches[i].FindingID, match.FindingID,
				"FindingID should be identical between first and cached scan")
		}
	}
}

// ---------------------------------------------------------------------------
// Custom path / datastore tests (ported from pkg/scanner/titus_datastore_test.go)
// ---------------------------------------------------------------------------

func TestExplicitPathUsed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "titus.db")

	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath}))
	defer s.Close()

	assert.Equal(t, dbPath, s.DBPath(), "DBPath should return provided path")
	_, err := os.Stat(dbPath)
	assert.NoError(t, err, "database file should exist at provided path")
}

func TestCustomPathPersistence(t *testing.T) {
	customPath := filepath.Join(t.TempDir(), "titus.db")

	content := []byte("test content for persistence")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test.txt"}

	// Create scanner with custom path and scan content
	var s1 SecretScanner
	require.NoError(t, s1.Start(ScannerConfig{DBPath: customPath}))

	initialMatches, err := s1.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent should succeed")

	// Close first scanner
	require.NoError(t, s1.Close())

	// Verify database file still exists at custom path
	_, err = os.Stat(customPath)
	require.NoError(t, err, "database file should persist after close")

	// Create new scanner with same custom path
	var s2 SecretScanner
	require.NoError(t, s2.Start(ScannerConfig{DBPath: customPath}))
	defer s2.Close()

	// Scan same content — should find it already exists
	cachedMatches, err := s2.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent with existing blob should succeed")
	assert.Equal(t, len(initialMatches), len(cachedMatches), "cached matches should have same count")
}

// ---------------------------------------------------------------------------
// Findings tests (ported from pkg/scanner/titus_test.go)
// ---------------------------------------------------------------------------

func TestFindingsCreation(t *testing.T) {
	// Pre-existing failure: Titus FK constraint error when storing matches for this content.

	s := startScanner(t)

	content := []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF")
	blobID := types.ComputeBlobID(content)
	provenance := types.FileProvenance{FilePath: "test/credentials.txt"}

	// Scan content — should detect and store matches
	matches, err := s.ps.scanContent(content, blobID, provenance)
	require.NoError(t, err, "scanContent should succeed")
	require.NotEmpty(t, matches, "should detect at least one match")

	// Verify findings were created in the database
	findings, err := s.ps.store.GetFindings()
	require.NoError(t, err, "GetFindings should succeed")
	assert.NotEmpty(t, findings, "should have created at least one finding")

	// Verify finding has correct structure
	for _, finding := range findings {
		assert.NotEmpty(t, finding.ID, "finding should have ID")
		assert.NotEmpty(t, finding.RuleID, "finding should have RuleID")
		assert.NotNil(t, finding.Groups, "finding should have Groups")
	}
}

func TestFindingsDeduplication(t *testing.T) {
	// Pre-existing failure: Titus FK constraint error when storing matches for this content.

	s := startScanner(t)

	// Same secret in two different files (different blobs via different provenance)
	content1 := []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF")
	blobID1 := types.ComputeBlobID(content1)
	provenance1 := types.FileProvenance{FilePath: "file1/credentials.txt"}

	content2 := []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF")
	blobID2 := types.ComputeBlobID(content2)
	provenance2 := types.FileProvenance{FilePath: "file2/credentials.txt"}

	// Scan first blob
	matches1, err := s.ps.scanContent(content1, blobID1, provenance1)
	require.NoError(t, err, "first scan should succeed")
	require.NotEmpty(t, matches1, "should detect matches in first file")

	// Scan second blob
	matches2, err := s.ps.scanContent(content2, blobID2, provenance2)
	require.NoError(t, err, "second scan should succeed")
	require.NotEmpty(t, matches2, "should detect matches in second file")

	// Should have matches but only 1 finding (deduplicated by secret value)
	findings, err := s.ps.store.GetFindings()
	require.NoError(t, err, "GetFindings should succeed")
	assert.Len(t, findings, 1, "should have exactly 1 deduplicated finding")
}

// ---------------------------------------------------------------------------
// Ignore pattern tests
// ---------------------------------------------------------------------------

func TestSecretScanner_ScanSkipsIgnoredPathFilterableInputs(t *testing.T) {
	s := startScanner(t)

	input := output.ScanInput{
		Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
		ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
		ResourceType:   "AWS::Lambda::Function",
		Region:         "us-east-1",
		AccountID:      "123456789012",
		Label:          "node_modules/@aws-sdk/client-s3/dist/credentials.js",
		PathFilterable: true,
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(input, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "scan results should be empty for ignored path-filterable input")
}

func TestSecretScanner_ScanDoesNotFilterNonPathFilterableInputs(t *testing.T) {
	s := startScanner(t)

	input := output.ScanInput{
		Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
		ResourceID:     "arn:aws:ecs:us-east-1:123456789012:task-definition/my-task:1",
		ResourceType:   "AWS::ECS::TaskDefinition",
		Region:         "us-east-1",
		AccountID:      "123456789012",
		Label:          "package-lock.json",
		PathFilterable: false,
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(input, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.NotEmpty(t, items, "non-PathFilterable input must not be filtered even if label matches ignore pattern")
}

func TestSecretScanner_ScanAllowsNonIgnoredPathFilterableInputs(t *testing.T) {
	s := startScanner(t)

	input := output.ScanInput{
		Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
		ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
		ResourceType:   "AWS::Lambda::Function",
		Region:         "us-east-1",
		AccountID:      "123456789012",
		Label:          "src/handler.py",
		PathFilterable: true,
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(input, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.NotEmpty(t, items, "scan results should not be empty for allowed path")
}

func TestSecretScanner_CustomIgnoreFileReplacesDefaults(t *testing.T) {
	ignoreFile := filepath.Join(t.TempDir(), "custom.conf")
	require.NoError(t, os.WriteFile(ignoreFile, []byte("src/**\n"), 0o644))

	dbPath := filepath.Join(t.TempDir(), "titus.db")
	var s SecretScanner
	require.NoError(t, s.Start(ScannerConfig{DBPath: dbPath, IgnoreFile: ignoreFile}))
	t.Cleanup(func() { s.Close() })

	srcInput := output.ScanInput{
		Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
		ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
		ResourceType:   "AWS::Lambda::Function",
		Region:         "us-east-1",
		AccountID:      "123456789012",
		Label:          "src/handler.py",
		PathFilterable: true,
	}

	out := pipeline.New[SecretScanResult]()
	go func() {
		defer out.Close()
		require.NoError(t, s.Scan(srcInput, out))
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "src/ should be ignored by custom pattern")

	nodeInput := output.ScanInput{
		Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
		ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
		ResourceType:   "AWS::Lambda::Function",
		Region:         "us-east-1",
		AccountID:      "123456789012",
		Label:          "node_modules/@aws-sdk/client-s3/dist/credentials.js",
		PathFilterable: true,
	}

	out2 := pipeline.New[SecretScanResult]()
	go func() {
		defer out2.Close()
		require.NoError(t, s.Scan(nodeInput, out2))
	}()
	items2, err := out2.Collect()
	require.NoError(t, err)
	assert.NotEmpty(t, items2, "node_modules should NOT be ignored when custom file replaces defaults")
}

func TestSecretScanner_ScanSkipsMultipleIgnoredPaths(t *testing.T) {
	s := startScanner(t)

	ignoredLabels := []string{
		"node_modules/@aws-sdk/client-s3/index.js",
		"package-lock.json",
		"vendor/bundle.min.js",
		"lib/python3.11/site-packages/botocore/auth.py",
		"go.sum",
	}

	for _, label := range ignoredLabels {
		t.Run(label, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:        []byte("aws_access_key_id=AKIADEADBEEFDEADBEEF"),
					ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType:   "AWS::Lambda::Function",
					Region:         "us-east-1",
					AccountID:      "123456789012",
					Label:          label,
					PathFilterable: true,
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)
			assert.Empty(t, items, "expected %s to be ignored", label)
		})
	}
}
