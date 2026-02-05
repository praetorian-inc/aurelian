# ApolloOfflineV2 Test Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `developing-with-tdd` to implement this test plan task-by-task.

**Goal:** Create comprehensive test coverage for `apollo_offline_v2.go` covering file loading, Run method, and builder pattern.

**Module Under Test:** `capabilities/modules/aurelian/pkg/modules/aws/recon/apollo_offline_v2.go`

**Reference Test:** `capabilities/modules/aurelian/pkg/modules/aws/recon/apollo_v2_test.go` for patterns.

**Target Coverage:** >70%

---

## Verified APIs (Evidence-Based Analysis)

### API: ApolloOfflineV2 Struct

**Source:** `apollo_offline_v2.go` (lines 16-25)
```go
type ApolloOfflineV2 struct {
    GaadFile             string
    OrgPolicyFile        string
    ResourcePoliciesFile string
}
```

### API: NewApolloOfflineV2

**Source:** `apollo_offline_v2.go` (lines 31-35)
```go
func NewApolloOfflineV2(gaadFile string) *ApolloOfflineV2 {
    return &ApolloOfflineV2{
        GaadFile: gaadFile,
    }
}
```

### API: WithOrgPolicyFile

**Source:** `apollo_offline_v2.go` (lines 38-41)
```go
func (a *ApolloOfflineV2) WithOrgPolicyFile(path string) *ApolloOfflineV2 {
    a.OrgPolicyFile = path
    return a
}
```

### API: WithResourcePoliciesFile

**Source:** `apollo_offline_v2.go` (lines 44-47)
```go
func (a *ApolloOfflineV2) WithResourcePoliciesFile(path string) *ApolloOfflineV2 {
    a.ResourcePoliciesFile = path
    return a
}
```

### API: Run

**Source:** `apollo_offline_v2.go` (lines 50-93)
```go
func (a *ApolloOfflineV2) Run(ctx context.Context) (*ApolloOfflineResult, error)
```
- Returns `(*ApolloOfflineResult, error)`
- Calls `loadOrgPolicies()`, `loadGaad()`, `loadResourcePolicies()`
- Uses `iam.NewGaadAnalyzer(pd)`

### API: loadGaad (internal)

**Source:** `apollo_offline_v2.go` (lines 121-146)
```go
func (a *ApolloOfflineV2) loadGaad() (*types.Gaad, error)
```
- Returns error if `GaadFile == ""`
- Tries array format first, then object format
- Returns error on empty array

### API: loadOrgPolicies (internal)

**Source:** `apollo_offline_v2.go` (lines 96-119)
```go
func (a *ApolloOfflineV2) loadOrgPolicies() (*orgpolicies.OrgPolicies, error)
```
- Returns `NewDefaultOrgPolicies()` if `OrgPolicyFile == ""`
- Tries array format first, then object format
- Returns default on empty array

### API: loadResourcePolicies (internal)

**Source:** `apollo_offline_v2.go` (lines 149-180)
```go
func (a *ApolloOfflineV2) loadResourcePolicies() (map[string]*types.Policy, error)
```
- Returns empty map if `ResourcePoliciesFile == ""`
- Tries array format first, then object format
- Returns empty map on empty array

---

## Test Plan

### Test File: `apollo_offline_v2_test.go`

Create in: `capabilities/modules/aurelian/pkg/modules/aws/recon/apollo_offline_v2_test.go`

---

## 1. Constructor and Builder Pattern Tests

### Test: TestNewApolloOfflineV2

**Purpose:** Verify constructor creates instance with correct GAAD file path.

**Test Cases:**

| Test Case | Input | Expected Output |
|-----------|-------|-----------------|
| Creates with GAAD file | `"/path/to/gaad.json"` | Instance with `GaadFile` set |
| Empty fields by default | Any path | `OrgPolicyFile` and `ResourcePoliciesFile` empty |

```go
func TestNewApolloOfflineV2(t *testing.T) {
    gaadPath := "/path/to/gaad.json"

    apollo := NewApolloOfflineV2(gaadPath)

    require.NotNil(t, apollo)
    assert.Equal(t, gaadPath, apollo.GaadFile)
    assert.Empty(t, apollo.OrgPolicyFile, "OrgPolicyFile should be empty by default")
    assert.Empty(t, apollo.ResourcePoliciesFile, "ResourcePoliciesFile should be empty by default")
}
```

**Exit Criteria:**
- [ ] 1 test function with 3 assertions (verify: `go test -v -run TestNewApolloOfflineV2`)

---

### Test: TestApolloOfflineV2_WithOrgPolicyFile

**Purpose:** Verify builder method sets org policy file and returns self for chaining.

```go
func TestApolloOfflineV2_WithOrgPolicyFile(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json")

    result := apollo.WithOrgPolicyFile("/path/to/policies.json")

    assert.Equal(t, "/path/to/policies.json", apollo.OrgPolicyFile)
    assert.Equal(t, apollo, result, "Should return self for method chaining")
}
```

**Exit Criteria:**
- [ ] 1 test function with 2 assertions

---

### Test: TestApolloOfflineV2_WithResourcePoliciesFile

**Purpose:** Verify builder method sets resource policies file and returns self for chaining.

```go
func TestApolloOfflineV2_WithResourcePoliciesFile(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json")

    result := apollo.WithResourcePoliciesFile("/path/to/resource-policies.json")

    assert.Equal(t, "/path/to/resource-policies.json", apollo.ResourcePoliciesFile)
    assert.Equal(t, apollo, result, "Should return self for method chaining")
}
```

**Exit Criteria:**
- [ ] 1 test function with 2 assertions

---

### Test: TestApolloOfflineV2_BuilderChaining

**Purpose:** Verify multiple builder methods can be chained together.

```go
func TestApolloOfflineV2_BuilderChaining(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json").
        WithOrgPolicyFile("/org.json").
        WithResourcePoliciesFile("/resources.json")

    assert.Equal(t, "/gaad.json", apollo.GaadFile)
    assert.Equal(t, "/org.json", apollo.OrgPolicyFile)
    assert.Equal(t, "/resources.json", apollo.ResourcePoliciesFile)
}
```

**Exit Criteria:**
- [ ] 1 test function with 3 assertions demonstrating fluent API

---

## 2. loadGaad Tests

### Test: TestLoadGaad_ValidObjectFormat

**Purpose:** Verify GAAD loads correctly when file contains a single object.

**Setup:** Create temp file with valid GAAD object JSON.

```go
func TestLoadGaad_ValidObjectFormat(t *testing.T) {
    // Create temp file with valid GAAD object
    gaadJSON := `{
        "UserDetailList": [{"UserName": "test-user"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
    tmpFile := createTempFile(t, gaadJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    gaad, err := apollo.loadGaad()

    require.NoError(t, err)
    require.NotNil(t, gaad)
    assert.Len(t, gaad.UserDetailList, 1)
}
```

**Exit Criteria:**
- [ ] Test passes with valid object format
- [ ] Correct number of users loaded

---

### Test: TestLoadGaad_ValidArrayFormat

**Purpose:** Verify GAAD loads correctly when file contains array format (first element used).

```go
func TestLoadGaad_ValidArrayFormat(t *testing.T) {
    gaadJSON := `[{
        "UserDetailList": [{"UserName": "array-user"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }]`
    tmpFile := createTempFile(t, gaadJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    gaad, err := apollo.loadGaad()

    require.NoError(t, err)
    require.NotNil(t, gaad)
    assert.Len(t, gaad.UserDetailList, 1)
}
```

**Exit Criteria:**
- [ ] Test passes with array format
- [ ] First element extracted correctly

---

### Test: TestLoadGaad_EmptyGaadFile

**Purpose:** Verify error returned when GaadFile path is empty string.

```go
func TestLoadGaad_EmptyGaadFile(t *testing.T) {
    apollo := NewApolloOfflineV2("")

    _, err := apollo.loadGaad()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "gaad-file is required")
}
```

**Exit Criteria:**
- [ ] Error returned with descriptive message

---

### Test: TestLoadGaad_MissingFile

**Purpose:** Verify error returned when file does not exist.

```go
func TestLoadGaad_MissingFile(t *testing.T) {
    apollo := NewApolloOfflineV2("/nonexistent/path/gaad.json")

    _, err := apollo.loadGaad()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to read GAAD file")
}
```

**Exit Criteria:**
- [ ] Error returned with file path in message

---

### Test: TestLoadGaad_EmptyArray

**Purpose:** Verify error returned when file contains empty JSON array.

```go
func TestLoadGaad_EmptyArray(t *testing.T) {
    tmpFile := createTempFile(t, "[]")
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    _, err := apollo.loadGaad()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "empty array")
}
```

**Exit Criteria:**
- [ ] Error returned when array is empty

---

### Test: TestLoadGaad_InvalidJSON

**Purpose:** Verify error returned when file contains invalid JSON.

```go
func TestLoadGaad_InvalidJSON(t *testing.T) {
    tmpFile := createTempFile(t, "not valid json {")
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    _, err := apollo.loadGaad()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to unmarshal")
}
```

**Exit Criteria:**
- [ ] Error returned with unmarshal failure message

---

## 3. loadOrgPolicies Tests

### Test: TestLoadOrgPolicies_NoFileProvided

**Purpose:** Verify default org policies returned when no file specified.

```go
func TestLoadOrgPolicies_NoFileProvided(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json")
    // OrgPolicyFile is empty by default

    policies, err := apollo.loadOrgPolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
    // Should be equivalent to NewDefaultOrgPolicies()
}
```

**Exit Criteria:**
- [ ] No error returned
- [ ] Non-nil default policies returned

---

### Test: TestLoadOrgPolicies_ValidObjectFormat

**Purpose:** Verify org policies load correctly from object format.

```go
func TestLoadOrgPolicies_ValidObjectFormat(t *testing.T) {
    orgJSON := `{
        "Policies": [{"PolicyName": "test-policy"}]
    }`
    tmpFile := createTempFile(t, orgJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
    policies, err := apollo.loadOrgPolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
}
```

**Exit Criteria:**
- [ ] Test passes with valid object format

---

### Test: TestLoadOrgPolicies_ValidArrayFormat

**Purpose:** Verify org policies load correctly from array format (first element used).

```go
func TestLoadOrgPolicies_ValidArrayFormat(t *testing.T) {
    orgJSON := `[{
        "Policies": [{"PolicyName": "array-policy"}]
    }]`
    tmpFile := createTempFile(t, orgJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
    policies, err := apollo.loadOrgPolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
}
```

**Exit Criteria:**
- [ ] Test passes with array format
- [ ] First element extracted correctly

---

### Test: TestLoadOrgPolicies_EmptyArrayReturnsDefault

**Purpose:** Verify default policies returned when file contains empty array.

```go
func TestLoadOrgPolicies_EmptyArrayReturnsDefault(t *testing.T) {
    tmpFile := createTempFile(t, "[]")
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithOrgPolicyFile(tmpFile)
    policies, err := apollo.loadOrgPolicies()

    require.NoError(t, err)
    require.NotNil(t, policies, "Should return default policies for empty array")
}
```

**Exit Criteria:**
- [ ] No error returned
- [ ] Default policies returned for empty array

---

### Test: TestLoadOrgPolicies_MissingFile

**Purpose:** Verify error returned when org policy file does not exist.

```go
func TestLoadOrgPolicies_MissingFile(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json").
        WithOrgPolicyFile("/nonexistent/org-policies.json")

    _, err := apollo.loadOrgPolicies()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to read org policies file")
}
```

**Exit Criteria:**
- [ ] Error returned with descriptive message

---

## 4. loadResourcePolicies Tests

### Test: TestLoadResourcePolicies_NoFileProvided

**Purpose:** Verify empty map returned when no resource policies file specified.

```go
func TestLoadResourcePolicies_NoFileProvided(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json")
    // ResourcePoliciesFile is empty by default

    policies, err := apollo.loadResourcePolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
    assert.Len(t, policies, 0)
}
```

**Exit Criteria:**
- [ ] No error returned
- [ ] Empty map returned

---

### Test: TestLoadResourcePolicies_ValidObjectFormat

**Purpose:** Verify resource policies load correctly from map format.

```go
func TestLoadResourcePolicies_ValidObjectFormat(t *testing.T) {
    policiesJSON := `{
        "arn:aws:s3:::bucket": {"Version": "2012-10-17", "Statement": []}
    }`
    tmpFile := createTempFile(t, policiesJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
    policies, err := apollo.loadResourcePolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
    assert.Len(t, policies, 1)
    assert.Contains(t, policies, "arn:aws:s3:::bucket")
}
```

**Exit Criteria:**
- [ ] Test passes with map format
- [ ] Correct number of policies loaded

---

### Test: TestLoadResourcePolicies_ValidArrayFormat

**Purpose:** Verify resource policies load correctly from array format (first element used).

```go
func TestLoadResourcePolicies_ValidArrayFormat(t *testing.T) {
    policiesJSON := `[{
        "arn:aws:s3:::bucket": {"Version": "2012-10-17", "Statement": []}
    }]`
    tmpFile := createTempFile(t, policiesJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
    policies, err := apollo.loadResourcePolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
    assert.Len(t, policies, 1)
}
```

**Exit Criteria:**
- [ ] Test passes with array format
- [ ] First element extracted correctly

---

### Test: TestLoadResourcePolicies_EmptyArrayReturnsEmptyMap

**Purpose:** Verify empty map returned when file contains empty array.

```go
func TestLoadResourcePolicies_EmptyArrayReturnsEmptyMap(t *testing.T) {
    tmpFile := createTempFile(t, "[]")
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2("/gaad.json").WithResourcePoliciesFile(tmpFile)
    policies, err := apollo.loadResourcePolicies()

    require.NoError(t, err)
    require.NotNil(t, policies)
    assert.Len(t, policies, 0)
}
```

**Exit Criteria:**
- [ ] No error returned
- [ ] Empty map returned for empty array

---

### Test: TestLoadResourcePolicies_MissingFile

**Purpose:** Verify error returned when resource policies file does not exist.

```go
func TestLoadResourcePolicies_MissingFile(t *testing.T) {
    apollo := NewApolloOfflineV2("/gaad.json").
        WithResourcePoliciesFile("/nonexistent/resource-policies.json")

    _, err := apollo.loadResourcePolicies()

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to read resource policies file")
}
```

**Exit Criteria:**
- [ ] Error returned with descriptive message

---

## 5. Run Method Tests

### Test: TestRun_MissingGaadFileReturnsError

**Purpose:** Verify Run returns error when GAAD file path is empty.

```go
func TestRun_MissingGaadFileReturnsError(t *testing.T) {
    apollo := NewApolloOfflineV2("")

    _, err := apollo.Run(context.Background())

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to load GAAD")
}
```

**Exit Criteria:**
- [ ] Error returned when GAAD file missing

---

### Test: TestRun_OptionalFilesMissingSucceeds

**Purpose:** Verify Run succeeds when optional files (org policies, resource policies) are not provided.

```go
func TestRun_OptionalFilesMissingSucceeds(t *testing.T) {
    // Create minimal valid GAAD file
    gaadJSON := `{
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
    tmpFile := createTempFile(t, gaadJSON)
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    // No OrgPolicyFile or ResourcePoliciesFile set

    result, err := apollo.Run(context.Background())

    require.NoError(t, err)
    require.NotNil(t, result)
}
```

**Exit Criteria:**
- [ ] No error returned with only GAAD file
- [ ] Non-nil result returned

---

### Test: TestRun_WithAllFilesSucceeds

**Purpose:** Verify Run succeeds when all files are provided and valid.

```go
func TestRun_WithAllFilesSucceeds(t *testing.T) {
    gaadJSON := `{
        "UserDetailList": [{"UserName": "test-user", "Path": "/", "UserId": "123", "Arn": "arn:aws:iam::123:user/test"}],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": []
    }`
    gaadFile := createTempFile(t, gaadJSON)
    defer os.Remove(gaadFile)

    orgJSON := `{"Policies": []}`
    orgFile := createTempFile(t, orgJSON)
    defer os.Remove(orgFile)

    resourceJSON := `{}`
    resourceFile := createTempFile(t, resourceJSON)
    defer os.Remove(resourceFile)

    apollo := NewApolloOfflineV2(gaadFile).
        WithOrgPolicyFile(orgFile).
        WithResourcePoliciesFile(resourceFile)

    result, err := apollo.Run(context.Background())

    require.NoError(t, err)
    require.NotNil(t, result)
}
```

**Exit Criteria:**
- [ ] No error returned with all files
- [ ] Non-nil result returned

---

### Test: TestRun_InvalidGaadFileReturnsError

**Purpose:** Verify Run returns error when GAAD file contains invalid JSON.

```go
func TestRun_InvalidGaadFileReturnsError(t *testing.T) {
    tmpFile := createTempFile(t, "invalid json")
    defer os.Remove(tmpFile)

    apollo := NewApolloOfflineV2(tmpFile)
    _, err := apollo.Run(context.Background())

    require.Error(t, err)
    assert.Contains(t, err.Error(), "failed to load GAAD")
}
```

**Exit Criteria:**
- [ ] Error returned with invalid GAAD file

---

## Test Helpers

### Helper: createTempFile

```go
func createTempFile(t *testing.T, content string) string {
    t.Helper()
    tmpFile, err := os.CreateTemp("", "apollo-test-*.json")
    require.NoError(t, err)

    _, err = tmpFile.WriteString(content)
    require.NoError(t, err)

    err = tmpFile.Close()
    require.NoError(t, err)

    return tmpFile.Name()
}
```

---

## Exit Criteria Summary

**Total Test Functions:** 21

| Category | Test Count |
|----------|------------|
| Constructor/Builder | 4 |
| loadGaad | 6 |
| loadOrgPolicies | 5 |
| loadResourcePolicies | 4 |
| Run | 4 |

**Verification Commands:**

```bash
# Run all tests
go test -v ./pkg/modules/aws/recon/... -run "TestApolloOfflineV2\|TestLoadGaad\|TestLoadOrgPolicies\|TestLoadResourcePolicies\|TestRun"

# Check coverage
go test -cover ./pkg/modules/aws/recon/... -coverprofile=coverage.out
go tool cover -func=coverage.out | grep apollo_offline_v2
```

**Coverage Target:** >70% on `apollo_offline_v2.go`

---

## Test Quality Checklist (per `avoiding-low-value-tests`)

- [x] **Happy path** - Normal successful operation (TestRun_WithAllFilesSucceeds)
- [x] **Empty/nil inputs** - Empty string paths (TestLoadGaad_EmptyGaadFile)
- [x] **Not found** - Missing files (TestLoadGaad_MissingFile, etc.)
- [x] **Invalid input** - Invalid JSON (TestLoadGaad_InvalidJSON)
- [x] **Boundary conditions** - Empty arrays (TestLoadGaad_EmptyArray)
- [x] **Error propagation** - Errors returned correctly (all error tests)

**No low-value tests:**
- No constant identity tests
- No trivial getter tests
- Tests verify behavior, not just structure
- All assertions verify meaningful outcomes

---

## Metadata

```json
{
  "agent": "test-lead",
  "output_type": "test-plan",
  "timestamp": "2026-02-04T20:49:04Z",
  "feature_directory": "capabilities/modules/aurelian/.capability-development",
  "skills_invoked": [
    "using-skills",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-testing",
    "persisting-agent-outputs",
    "writing-plans",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni",
    "developing-with-tdd",
    "discovering-reusable-code",
    "debugging-systematically",
    "using-todowrite"
  ],
  "library_skills_read": [
    ".claude/skill-library/testing/testing-anti-patterns/SKILL.md",
    ".claude/skill-library/testing/behavior-vs-implementation-testing/SKILL.md",
    ".claude/skill-library/testing/avoiding-low-value-tests/SKILL.md"
  ],
  "source_files_verified": [
    "capabilities/modules/aurelian/pkg/modules/aws/recon/apollo_offline_v2.go:1-183",
    "capabilities/modules/aurelian/pkg/modules/aws/recon/apollo_v2_test.go:1-106"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-tester",
    "context": "Implement tests from this plan following TDD workflow"
  }
}
```
