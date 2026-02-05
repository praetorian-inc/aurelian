# Code Review: ApolloOfflineV2

**Reviewer:** capability-reviewer
**Date:** 2026-02-04
**Capability:** apollo_offline_v2 (AWS IAM offline analysis)

---

## Review Result
REVIEW_REJECTED

---

## Executive Summary

The `apollo_offline_v2.go` implementation **DOES NOT COMPILE** due to a critical type alias error on line 31. The code cannot be used in its current state. Beyond the compilation failure, the implementation demonstrates good V2 pattern adherence and properly mirrors `apollo_v2.go` architecture.

---

## 1. Plan Adherence

**Plan Location:** No explicit architecture plan found. Reviewing against implicit V2 pattern requirements and reference implementation `apollo_v2.go`.

### Implicit Requirements

| Requirement                  | Status | Notes                                                            |
| ---------------------------- | ------ | ---------------------------------------------------------------- |
| No Janus framework imports   | ✅      | Correctly removed janus-framework dependencies                   |
| Plain Go struct pattern      | ✅      | Uses `ApolloOfflineV2` struct with public fields                 |
| `Run(ctx) (*Result, error)`  | ✅      | Implements standard V2 method signature                          |
| Builder pattern (optional)   | ✅      | Provides `WithOrgPolicyFile()`, `WithResourcePoliciesFile()`     |
| Reuse existing analyzers     | ✅      | Uses `iam.NewGaadAnalyzer()` and `awstransformers` as intended   |
| Consistent with apollo_v2.go | ❌      | Type alias breaks, but logic structure matches well              |
| Proper error wrapping        | ✅      | Uses `fmt.Errorf("context: %w", err)` throughout                 |
| File loading handles formats | ✅      | Tries array format first, falls back to object (matches online)  |

---

## 2. Code Quality Issues

### CRITICAL Issues

| Severity | Issue                                                        | Location                | Action                                                               |
| -------- | ------------------------------------------------------------ | ----------------------- | -------------------------------------------------------------------- |
| CRITICAL | **Type alias breaks compilation**: `ApolloResult` not defined at line 31 | `apollo_offline_v2.go:31` | Move `ApolloResult` definition BEFORE `ApolloOfflineResult` alias or define inline |
| CRITICAL | Build failure: All references to `result.Permissions` fail   | `apollo_offline_v2.go:97,102,104` | Fix requires correcting type alias or inlining struct definition     |

**Root Cause Analysis:**

The code defines `type ApolloOfflineResult = ApolloResult` on line 31, but `ApolloResult` is defined **in apollo_v2.go** (lines 39-48), not imported or declared earlier in this file. The type alias creates a forward reference to a type that doesn't exist in the compilation unit.

**Evidence:**

```bash
$ GOWORK=off go build ./pkg/modules/aws/recon/apollo_offline_v2.go
# command-line-arguments
pkg/modules/aws/recon/apollo_offline_v2.go:31:28: undefined: ApolloResult
pkg/modules/aws/recon/apollo_offline_v2.go:97:38: result.Permissions undefined
...
```

**Fix Options:**

1. **Option A (Recommended):** Define the result type inline:
   ```go
   type ApolloOfflineResult struct {
       Permissions              []interface{}
       GitHubActionsPermissions []*output.GitHubActionsPermission
   }
   ```

2. **Option B:** Import/export `ApolloResult` from a shared location (requires refactoring apollo_v2.go)

### HIGH Issues

| Severity | Issue                                            | Location                | Action                               |
| -------- | ------------------------------------------------ | ----------------------- | ------------------------------------ |
| HIGH     | Silent error swallowing on line 102              | `apollo_offline_v2.go:102` | Log or return error from `ExtractGitHubActionsPermissions` |
| HIGH     | Silent error swallowing on line 95               | `apollo_offline_v2.go:95`  | Log skipped permissions with reason |
| HIGH     | Empty file check missing for GAAD                | `apollo_offline_v2.go:162` | Add check: `if len(fileBytes) == 0` |

### MEDIUM Issues

| Severity | Issue                                          | Location                | Action                              |
| -------- | ---------------------------------------------- | ----------------------- | ----------------------------------- |
| MEDIUM   | Deprecation notice unclear in offline.go       | `apollo_offline.go:15`  | Add comment pointing to v2 file     |
| MEDIUM   | No context usage in Run() method               | `apollo_offline_v2.go:55` | Pass ctx to underlying operations (currently unused) |

---

## 3. V2 Pattern Compliance

### ✅ Correct V2 Patterns

1. **No Janus imports** - Properly removed `janus-framework` dependencies
2. **Plain Go struct** - Uses simple `ApolloOfflineV2` struct with exported fields
3. **Builder pattern** - Provides `New*()` constructor and `With*()` methods
4. **Method signature** - `Run(ctx context.Context) (*Result, error)` matches V2 standard
5. **Error handling** - Uses `fmt.Errorf("context: %w", err)` for wrapped errors
6. **Logging** - Uses `slog.Info/Warn` appropriately
7. **File format flexibility** - Handles both array and object JSON formats

### ✅ Consistency with Reference Implementation (apollo_v2.go)

The implementation correctly mirrors apollo_v2.go:

| Pattern                     | apollo_v2.go Location | apollo_offline_v2.go Location | Status |
| --------------------------- | --------------------- | ----------------------------- | ------ |
| `loadOrgPolicies()`         | Lines 178-209         | Lines 110-138                 | ✅ Identical logic |
| Array-first unmarshal       | Lines 192-199         | Lines 122-129                 | ✅ Same pattern |
| Default org policies        | Line 183, 198         | Line 113, 128                 | ✅ Consistent |
| `NewGaadAnalyzer(pd)`       | Line 130              | Line 84                       | ✅ Reused correctly |
| `TransformResultToPermission` | Line 139            | Line 93                       | ✅ Reused correctly |
| `ExtractGitHubActionsPermissions` | Line 150        | Line 101                      | ✅ Reused correctly |

**Example (loadOrgPolicies comparison):**

**apollo_v2.go:178-209 (reference)**
```go
func (a *ApolloV2) loadOrgPolicies() (*orgpolicies.OrgPolicies, error) {
    if a.OrgPolicyFile == "" {
        slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
        return orgpolicies.NewDefaultOrgPolicies(), nil
    }
    // ... array unmarshal logic ...
}
```

**apollo_offline_v2.go:110-138 (implementation)**
```go
func (a *ApolloOfflineV2) loadOrgPolicies() (*orgpolicies.OrgPolicies, error) {
    if a.OrgPolicyFile == "" {
        slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
        return orgpolicies.NewDefaultOrgPolicies(), nil
    }
    // ... identical array unmarshal logic ...
}
```

**Verdict:** The logic is correctly duplicated with only struct receiver type differences (expected for separate modules).

---

## 4. File Loading Logic Review

### Array vs Object Format Handling

The code correctly implements the "try array first, fallback to object" pattern used in apollo_v2.go:

**Org Policies (lines 121-137):**
```go
// Try array first (matches online module output)
var orgPoliciesArray []*orgpolicies.OrgPolicies
if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
    if len(orgPoliciesArray) > 0 {
        return orgPoliciesArray[0], nil
    }
    // ... default ...
}
// Fallback to single object
```

**GAAD (lines 151-166):**
```go
// Try array first (matches account-auth-details module output)
var gaadArray []types.Gaad
if err := json.Unmarshal(fileBytes, &gaadArray); err == nil {
    if len(gaadArray) > 0 {
        return &gaadArray[0], nil
    }
    return nil, fmt.Errorf("GAAD file '%s' contains empty array", a.GaadFile)
}
// Fallback to single object
```

**Resource Policies (lines 181-201):**
```go
// Try array first
var resourcePoliciesArray []map[string]*types.Policy
if err := json.Unmarshal(fileBytes, &resourcePoliciesArray); err == nil {
    if len(resourcePoliciesArray) > 0 {
        return resourcePoliciesArray[0], nil
    }
    // ... default ...
}
// Parse as map directly
```

### ✅ Strengths

1. **Consistent pattern** across all three loaders
2. **Clear comments** explaining expected format ("matches online module output")
3. **Proper defaults** for optional files (org policies, resource policies)
4. **Clear error messages** with file paths included

### ❌ Issues

1. **Line 95:** `continue` silently drops permissions that fail transformation (should log reason)
2. **Line 102:** `_` ignores errors from `ExtractGitHubActionsPermissions` (should log)
3. **Empty array handling** differs between GAAD (error) and org policies (default) - inconsistent

---

## 5. DRY Assessment

### Violation: Duplicated loadOrgPolicies()

**Evidence:** `apollo_v2.go:178-209` and `apollo_offline_v2.go:110-138` contain identical logic (60 lines duplicated).

**Justification:** Acceptable duplication because:
- The methods belong to different struct receivers (`ApolloV2` vs `ApolloOfflineV2`)
- Extracting to shared function requires receiver interface or passing fields
- V2 pattern emphasizes simplicity over DRY

**Recommendation:** Document this as intentional duplication (add comment referencing apollo_v2.go).

### Reuse Success

The code correctly **reuses** existing packages instead of duplicating:
- ✅ `iam.NewGaadAnalyzer()` - No custom analyzer
- ✅ `awstransformers.TransformResultToPermission()` - No custom transformation
- ✅ `awstransformers.ExtractGitHubActionsPermissions()` - No custom extraction
- ✅ `orgpolicies.NewDefaultOrgPolicies()` - No hardcoded defaults

---

## 6. Verification Results

### Static Analysis

- **go vet**: ❌ FAILED (undefined: ApolloResult)
- **Build**: ❌ FAILED (5 compilation errors)
- **Linting**: Not run (blocked by compilation failure)

### Test Coverage

No tests found for `apollo_offline_v2.go`. Tests required:
- Unit tests for file loading (array/object formats)
- Error handling tests (missing files, malformed JSON)
- Integration test with sample GAAD/org policy files

**Recommendation:** Add tests in `apollo_offline_v2_test.go` following patterns from `apollo_v2_test.go`.

---

## 7. Documentation Quality

### ✅ Strengths

- **Clear package comment** on line 16-18 explaining purpose
- **Field comments** on lines 20-27 documenting required vs optional
- **Function comments** on lines 33-34, 54-55, 109, 140, 169
- **Inline comments** explaining logic (e.g., "Try to unmarshal as array first")

### ❌ Gaps

- No usage example in comments (apollo_v2.go has detailed examples in README_V2.md)
- Builder pattern methods lack examples
- No migration guide from V1 apollo_offline

**Recommendation:** Add usage example in package comment or create `README_APOLLO_OFFLINE_V2.md`.

---

## 8. Comparison with apollo_v2.go (Reference Implementation)

### Structural Alignment

| Aspect                | apollo_v2.go                      | apollo_offline_v2.go          | Match? |
| --------------------- | --------------------------------- | ----------------------------- | ------ |
| Package               | `recon`                           | `recon`                       | ✅      |
| Struct pattern        | Plain Go struct with fields       | Plain Go struct with fields   | ✅      |
| Constructor           | `NewApolloV2(profile, regions)`   | `NewApolloOfflineV2(gaadFile)`| ✅      |
| Builder methods       | `WithOrgPolicyFile()`, `With*`    | `WithOrgPolicyFile()`, `With*`| ✅      |
| Run signature         | `Run(ctx) (*ApolloResult, error)` | `Run(ctx) (*ApolloOfflineResult, error)` | ✅ |
| Error wrapping        | `fmt.Errorf("context: %w", err)`  | Same                          | ✅      |
| Logging               | `slog.Info/Warn`                  | Same                          | ✅      |
| Analyzer reuse        | `iam.NewGaadAnalyzer(pd)`         | Same                          | ✅      |

### Logic Differences (Expected)

1. **Initialization:** apollo_v2 initializes AWS clients; offline reads from files
2. **GAAD source:** apollo_v2 calls AWS API; offline loads from JSON file
3. **Resources:** apollo_v2 enumerates via CloudControl; offline uses empty array
4. **Result type:** apollo_v2 includes `ResourceRoleRelationships`; offline does not (acceptable - no resources to map)

### Logic Differences (Issues)

1. **Context usage:** apollo_v2 passes ctx to AWS SDK calls; offline ignores ctx (MEDIUM issue)
2. **Resource policies:** apollo_v2 fetches dynamically; offline loads from file (correct behavior)

---

## 9. Security Review

### Input Validation

| Input                  | Validation                        | Status |
| ---------------------- | --------------------------------- | ------ |
| `GaadFile` (required)  | Checked for empty string (line 142) | ✅      |
| `OrgPolicyFile` (opt)  | Defaults to `NewDefaultOrgPolicies()` | ✅      |
| `ResourcePoliciesFile` | Defaults to empty map (line 172)  | ✅      |
| JSON unmarshal errors  | Wrapped with file path context    | ✅      |

### Error Exposure

| Location | Risk                                  | Severity | Action |
| -------- | ------------------------------------- | -------- | ------ |
| Line 118 | File path in error (info disclosure?) | LOW      | Acceptable for CLI tool (no remote attacker) |
| Line 148 | File path in error                    | LOW      | Same as above |

**Verdict:** No critical security issues. Error messages appropriately include file paths for debugging (acceptable for local CLI tool).

---

## 10. Verdict

**CHANGES REQUIRED** before approval.

### Blocking Issues (Must Fix)

1. **CRITICAL:** Fix `ApolloOfflineResult = ApolloResult` type alias (line 31)
   - **Action:** Define result struct inline or move `ApolloResult` to shared location
   - **Blocker:** Code does not compile

### High-Priority Issues (Should Fix)

2. **HIGH:** Log or return error from `ExtractGitHubActionsPermissions` (line 102)
3. **HIGH:** Log reason when skipping permissions (line 95)
4. **HIGH:** Add empty file check for GAAD (line 162)
5. **Add tests:** Create `apollo_offline_v2_test.go` with:
   - Array format loading test
   - Object format loading test
   - Missing file error test
   - Empty file error test

### Nice-to-Have (Recommended)

6. **MEDIUM:** Add comment documenting DRY duplication with apollo_v2.go
7. **MEDIUM:** Pass `ctx` to operations that support context (currently unused)
8. **MEDIUM:** Create `README_APOLLO_OFFLINE_V2.md` with usage examples

---

## 11. Escalation

**Blocked:** CRITICAL compilation failure
**Attempted:** Code review, static analysis, comparison with reference implementation
**Recommend:** `capability-developer` to fix type alias and add tests

---

## 12. Next Steps

### For Developer

1. Fix type alias on line 31 (choose Option A or B from Critical Issues)
2. Run `GOWORK=off go build ./pkg/modules/aws/recon/apollo_offline_v2.go` to verify compilation
3. Address HIGH severity issues (error logging)
4. Add test coverage following `apollo_v2_test.go` patterns
5. Re-submit for review

### Acceptance Criteria for Re-Review

- [ ] Code compiles successfully with `GOWORK=off go build`
- [ ] All references to `result.Permissions` and `result.GitHubActionsPermissions` resolve
- [ ] `apollo_offline_v2_test.go` exists with >70% coverage
- [ ] Error logging added for lines 95, 102
- [ ] Empty file check added for GAAD loading

---

## Metadata

```json
{
  "agent": "capability-reviewer",
  "output_type": "code-review",
  "timestamp": "2026-02-04T20:30:00Z",
  "skills_invoked": [
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "reviewing-capability-implementations",
    "adhering-to-dry"
  ],
  "source_files_verified": [
    "apollo_offline_v2.go:1-203",
    "apollo_offline.go:1-38",
    "apollo_v2.go:1-281"
  ],
  "status": "blocked",
  "blocked_reason": "compilation_failure",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Fix CRITICAL type alias error on line 31, add error logging, and create tests"
  }
}
```
