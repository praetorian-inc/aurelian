# Nebula vs aurelian AWS Command Comparison Plan

## Executive Summary

This plan validates that **modules/aurelian** produces equivalent outputs to **modules/nebula** for all AWS commands. Both tools share the same Janus Framework foundation and have identical module counts (22 AWS modules each), but differ in implementation details.

---

## 1. Module Inventory

### AWS Commands (22 total per tool)

| Category | Module ID | Nebula Command | aurelian Command | Type |
|----------|-----------|----------------|-------------------|------|
| **recon** | whoami | `nebula aws recon whoami` | `aurelian aws recon whoami` | auto-run |
| **recon** | account-auth-details | `nebula aws recon account-auth-details` | `aurelian aws recon account-auth-details` | auto-run |
| **recon** | list | `nebula aws recon list` | `aurelian aws recon list` | input |
| **recon** | list-all | `nebula aws recon list-all` | `aurelian aws recon list-all` | input |
| **recon** | summary | `nebula aws recon summary` | `aurelian aws recon summary` | auto-run |
| **recon** | public-resources | `nebula aws recon public-resources` | `aurelian aws recon public-resources` | input |
| **recon** | public-resources-single | `nebula aws recon public-resources-single` | `aurelian aws recon public-resources-single` | input |
| **recon** | apollo | `nebula aws recon apollo` | `aurelian aws recon apollo` | input |
| **recon** | apollo-offline | `nebula aws recon apollo-offline` | `aurelian aws recon apollo-offline` | input |
| **recon** | find-secrets | `nebula aws recon find-secrets` | `aurelian aws recon find-secrets` | input |
| **recon** | find-secrets-resource | `nebula aws recon find-secrets-resource` | `aurelian aws recon find-secrets-resource` | input |
| **recon** | resource-policies | `nebula aws recon resource-policies` | `aurelian aws recon resource-policies` | auto-run |
| **recon** | org-policies | `nebula aws recon org-policies` | `aurelian aws recon org-policies` | auto-run |
| **recon** | get-console | `nebula aws recon get-console` | `aurelian aws recon get-console` | input |
| **recon** | ecr-dump | `nebula aws recon ecr-dump` | `aurelian aws recon ecr-dump` | auto-run |
| **recon** | cdk-bucket-takeover | `nebula aws recon cdk-bucket-takeover` | `aurelian aws recon cdk-bucket-takeover` | auto-run |
| **recon** | cloudfront-s3-takeover | `nebula aws recon cloudfront-s3-takeover` | `aurelian aws recon cloudfront-s3-takeover` | auto-run |
| **recon** | ec2-screenshot-analysis | `nebula aws recon ec2-screenshot-analysis` | `aurelian aws recon ec2-screenshot-analysis` | input |
| **analyze** | ip-lookup | `nebula aws analyze ip-lookup` | `aurelian aws analyze ip-lookup` | input |
| **analyze** | access-key-to-account-id | `nebula aws analyze access-key-to-account-id` | `aurelian aws analyze access-key-to-account-id` | input |
| **analyze** | known-account-id | `nebula aws analyze known-account-id` | `aurelian aws analyze known-account-id` | input |
| **analyze** | apollo-query | `nebula aws analyze apollo-query` | `aurelian aws analyze apollo-query` | input |
| **analyze** | expand-actions | `nebula aws analyze expand-actions` | `aurelian aws analyze expand-actions` | input |

**Note**: All command names are identical between nebula and aurelian. Go filenames may differ (e.g., `list_all_resources.go`) but the CLI command IDs (defined via `"id"` in module metadata) are the same.

---

## 2. Test Infrastructure Setup

### 2.1 Prerequisites

```bash
# Build both binaries
cd modules/nebula && go build -o nebula .
cd modules/aurelian && go build -o aurelian .

# Verify builds
./modules/nebula/nebula --version
./modules/aurelian/aurelian version

# AWS credentials (use same profile for both)
export AWS_PROFILE=test-profile
aws sts get-caller-identity  # Verify credentials work
```

### 2.2 Output Directory Structure

```bash
mkdir -p comparison-tests/{nebula,aurelian,diffs}
export NEBULA_OUT="comparison-tests/nebula"
export aurelian_OUT="comparison-tests/aurelian"
export DIFF_OUT="comparison-tests/diffs"
```

### 2.3 Common Test Parameters

```bash
# Standardize parameters for consistent comparison
export TEST_REGIONS="us-east-1"
export TEST_RESOURCE_TYPE="AWS::S3::Bucket"
export TEST_IP="52.94.76.1"  # Known AWS IP
export TEST_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"  # Example key format
export TEST_ACCOUNT_ID="123456789012"  # Test account
export TEST_ACTION="s3:GetObject"
export TEST_QUERY="MATCH (n) RETURN n LIMIT 10"  # Apollo graph query
export AWS_PROFILE="${AWS_PROFILE:-default}"  # AWS profile for commands requiring -p
```

---

## 3. Test Execution Strategy

### 3.1 Phase 1: Auto-Run Commands (No Input Required)

These commands run without explicit input parameters:

> **⚠️ Note**: `resource-policies` uses chain input for resource-type. When run standalone,
> it may enumerate all supported resource types or require upstream input. Test behavior
> may vary from chained execution.

```bash
# Test script: phase1_autorun.sh

AUTORUN_COMMANDS=(
    "whoami"
    "account-auth-details"
    "summary"
    "resource-policies"     # Note: Uses chain input, standalone behavior may vary
    "org-policies"          # CORRECTED: was "get-orgpolicies"
    "ecr-dump"
    "cdk-bucket-takeover"
    "cloudfront-s3-takeover"
)

for cmd in "${AUTORUN_COMMANDS[@]}"; do
    echo "Testing: aws recon $cmd"

    # Nebula - uses --output (dir) and --outfile (name)
    ./modules/nebula/nebula aws recon "$cmd" \
        --output "$NEBULA_OUT" \
        --outfile "${cmd}.json" \
        --quiet \
        2>&1 | tee "$NEBULA_OUT/${cmd}.log"

    # aurelian - outputs to aurelian-output/ directory by default
    # Note: --output-format is NOT a valid flag, aurelian auto-outputs JSON
    ./modules/aurelian/aurelian aws recon "$cmd" \
        --quiet \
        2>&1 | tee "$aurelian_OUT/${cmd}.log"

    # Move aurelian output to comparison dir
    mv aurelian-output/*.json "$aurelian_OUT/${cmd}.json" 2>/dev/null || true
done
```

### 3.2 Phase 2: Region/Resource-Type Commands

Commands requiring region and/or resource type parameters:

> **⚠️ CORRECTED**: Several commands were using incorrect flags. Key fixes:
> - `list`: Only accepts `-t` (resource-type), NO regions flag
> - `public-resources`: Uses chain input for resource-type, only has `-p` (profile) and `-o` (org-policies)
> - `apollo`: Uses chain input for resource-type, NO direct flags
> - aurelian: Does NOT have `--output-format` flag, outputs to `aurelian-output/` automatically

```bash
# Test script: phase2_resource_commands.sh

# list command - CORRECTED: only takes -t, NO -r/--regions flag
./modules/nebula/nebula aws recon list \
    -t "$TEST_RESOURCE_TYPE" \
    --output "$NEBULA_OUT" \
    --outfile "list.json" \
    --quiet

./modules/aurelian/aurelian aws recon list \
    -t "$TEST_RESOURCE_TYPE" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/list.json" 2>/dev/null || true

# list-all - has -s (scan-type), -r (regions), -p (profile), -f (filename)
./modules/nebula/nebula aws recon list-all \
    -s summary \
    -r "$TEST_REGIONS" \
    --output "$NEBULA_OUT" \
    --outfile "list-all.json" \
    --quiet

./modules/aurelian/aurelian aws recon list-all \
    -s summary \
    -r "$TEST_REGIONS" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/list-all.json" 2>/dev/null || true

# public-resources - CORRECTED: Uses chain input for resource-type
# Available flags: -p (profile), -o (org-policies file)
# When run standalone, behavior depends on whether chain input is required
# Test: Run with just profile to see standalone behavior
./modules/nebula/nebula aws recon public-resources \
    -p "$AWS_PROFILE" \
    --output "$NEBULA_OUT" \
    --outfile "public-resources.json" \
    --quiet

./modules/aurelian/aurelian aws recon public-resources \
    -p "$AWS_PROFILE" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/public-resources.json" 2>/dev/null || true

# apollo - CORRECTED: Uses chain input for resource-type, NO -t flag
# This command typically runs as part of a chain: list -> apollo
# Standalone test: May error or use default behavior - document actual behavior
echo "WARNING: apollo uses chain input. Standalone test may behave differently."
./modules/nebula/nebula aws recon apollo \
    --output "$NEBULA_OUT" \
    --outfile "apollo.json" \
    --quiet 2>&1 || echo "Nebula apollo standalone: requires chain input"

./modules/aurelian/aurelian aws recon apollo \
    --quiet 2>&1 || echo "aurelian apollo standalone: requires chain input"
mv aurelian-output/*.json "$aurelian_OUT/apollo.json" 2>/dev/null || true

# find-secrets - CORRECT: has -t (resource-type), -p (profile), --max-events, --max-streams
./modules/nebula/nebula aws recon find-secrets \
    -t "AWS::Lambda::Function" \
    --output "$NEBULA_OUT" \
    --outfile "find-secrets.json" \
    --quiet

./modules/aurelian/aurelian aws recon find-secrets \
    -t "AWS::Lambda::Function" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/find-secrets.json" 2>/dev/null || true
```

### 3.3 Phase 3: Analyze Commands (Input-Specific)

> **⚠️ CORRECTED**: Use short flags for consistency and remove invalid `--output-format` from aurelian.
> Both tools use the same short flags: `-i` (ip/account-id), `-k` (access-key-id), `-a` (action), `-q` (query).

```bash
# Test script: phase3_analyze_commands.sh

# ip-lookup - uses -i for IP address
./modules/nebula/nebula aws analyze ip-lookup \
    -i "$TEST_IP" \
    --output "$NEBULA_OUT" \
    --outfile "ip-lookup.json" \
    --quiet

./modules/aurelian/aurelian aws analyze ip-lookup \
    -i "$TEST_IP" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/ip-lookup.json" 2>/dev/null || true

# access-key-to-account-id - uses -k for access key
./modules/nebula/nebula aws analyze access-key-to-account-id \
    -k "$TEST_ACCESS_KEY" \
    --output "$NEBULA_OUT" \
    --outfile "access-key-to-account-id.json" \
    --quiet

./modules/aurelian/aurelian aws analyze access-key-to-account-id \
    -k "$TEST_ACCESS_KEY" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/access-key-to-account-id.json" 2>/dev/null || true

# known-account-id - uses -i for account ID
./modules/nebula/nebula aws analyze known-account-id \
    -i "$TEST_ACCOUNT_ID" \
    --output "$NEBULA_OUT" \
    --outfile "known-account-id.json" \
    --quiet

./modules/aurelian/aurelian aws analyze known-account-id \
    -i "$TEST_ACCOUNT_ID" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/known-account-id.json" 2>/dev/null || true

# apollo-query - uses -q for query (Nebula) or --query (aurelian has no short form)
./modules/nebula/nebula aws analyze apollo-query \
    -q "$TEST_QUERY" \
    --output "$NEBULA_OUT" \
    --outfile "apollo-query.json" \
    --quiet

./modules/aurelian/aurelian aws analyze apollo-query \
    --query "$TEST_QUERY" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/apollo-query.json" 2>/dev/null || true

# expand-actions - uses -a for action
./modules/nebula/nebula aws analyze expand-actions \
    -a "$TEST_ACTION" \
    --output "$NEBULA_OUT" \
    --outfile "expand-actions.json" \
    --quiet

./modules/aurelian/aurelian aws analyze expand-actions \
    -a "$TEST_ACTION" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/expand-actions.json" 2>/dev/null || true
```

### 3.4 Phase 4: Complex/Optional Commands

Commands requiring special setup or optional parameters:

> **⚠️ CORRECTED**:
> - `get-console` uses `-p` (profile) and `-r` (regions), NOT `--role-arn`
> - `apollo-offline` uses chain input, not explicit file flags when run standalone
> - Removed invalid `--output-format` from aurelian commands

```bash
# Test script: phase4_special_commands.sh

# get-console - CORRECTED: uses -p (profile) and -r (regions), NOT --role-arn
# This generates a federated console sign-in URL using current credentials
./modules/nebula/nebula aws recon get-console \
    -p "$AWS_PROFILE" \
    -r "$TEST_REGIONS" \
    --output "$NEBULA_OUT" \
    --outfile "get-console.json" \
    --quiet

./modules/aurelian/aurelian aws recon get-console \
    -p "$AWS_PROFILE" \
    -r "$TEST_REGIONS" \
    --quiet
mv aurelian-output/*.json "$aurelian_OUT/get-console.json" 2>/dev/null || true

# apollo-offline - CORRECTED: Uses chain input parameters
# Available flags: -o (org-policies), -g (gaad-file), -rp (resource-policies-file)
# These are optional inputs that supplement the chain
if [[ -f "test-data/gaad.json" ]]; then
    ./modules/nebula/nebula aws recon apollo-offline \
        -g "test-data/gaad.json" \
        --output "$NEBULA_OUT" \
        --outfile "apollo-offline.json" \
        --quiet

    ./modules/aurelian/aurelian aws recon apollo-offline \
        -g "test-data/gaad.json" \
        --quiet
    mv aurelian-output/*.json "$aurelian_OUT/apollo-offline.json" 2>/dev/null || true
else
    echo "SKIP: apollo-offline - test-data/gaad.json not found"
fi

# ec2-screenshot-analysis - has --anthropic-api-key, --anthropic-model, etc.
if [[ -n "$ANTHROPIC_API_KEY" ]]; then
    ./modules/nebula/nebula aws recon ec2-screenshot-analysis \
        --anthropic-api-key "$ANTHROPIC_API_KEY" \
        --output "$NEBULA_OUT" \
        --outfile "ec2-screenshot-analysis.json" \
        --quiet

    ./modules/aurelian/aurelian aws recon ec2-screenshot-analysis \
        --anthropic-api-key "$ANTHROPIC_API_KEY" \
        --quiet
    mv aurelian-output/*.json "$aurelian_OUT/ec2-screenshot-analysis.json" 2>/dev/null || true
else
    echo "SKIP: ec2-screenshot-analysis - ANTHROPIC_API_KEY not set"
fi

# public-resources-single - requires specific resource ARN
# Example: test with a known S3 bucket ARN
if [[ -n "$TEST_RESOURCE_ARN" ]]; then
    ./modules/nebula/nebula aws recon public-resources-single \
        -a "$TEST_RESOURCE_ARN" \
        --output "$NEBULA_OUT" \
        --outfile "public-resources-single.json" \
        --quiet

    ./modules/aurelian/aurelian aws recon public-resources-single \
        -a "$TEST_RESOURCE_ARN" \
        --quiet
    mv aurelian-output/*.json "$aurelian_OUT/public-resources-single.json" 2>/dev/null || true
else
    echo "SKIP: public-resources-single - TEST_RESOURCE_ARN not set"
fi

# find-secrets-resource - requires specific resource ARN
if [[ -n "$TEST_RESOURCE_ARN" ]]; then
    ./modules/nebula/nebula aws recon find-secrets-resource \
        -a "$TEST_RESOURCE_ARN" \
        --output "$NEBULA_OUT" \
        --outfile "find-secrets-resource.json" \
        --quiet

    ./modules/aurelian/aurelian aws recon find-secrets-resource \
        -a "$TEST_RESOURCE_ARN" \
        --quiet
    mv aurelian-output/*.json "$aurelian_OUT/find-secrets-resource.json" 2>/dev/null || true
else
    echo "SKIP: find-secrets-resource - TEST_RESOURCE_ARN not set"
fi
```

---

## 4. Output Comparison Methodology

### 4.1 JSON Normalization Script

```bash
#!/bin/bash
# normalize_json.sh - Normalize JSON for comparison

normalize_json() {
    local input="$1"
    local output="$2"

    # Remove timestamps, UUIDs, and other non-deterministic fields
    jq -S '
        walk(
            if type == "object" then
                del(.timestamp, .created_at, .updated_at, .execution_time,
                    .cache_hit, .request_id, .trace_id)
            else
                .
            end
        ) |
        # Sort arrays for consistent comparison
        walk(
            if type == "array" then
                sort_by(
                    if type == "object" then .name // .id // .key // .
                    else .
                    end
                )
            else
                .
            end
        )
    ' "$input" > "$output"
}
```

### 4.2 Comparison Script

```bash
#!/bin/bash
# compare_outputs.sh - Compare nebula vs aurelian outputs

COMMANDS=(
    "whoami"
    "account-auth-details"
    "list"
    "list-all"
    "summary"
    "public-resources"
    "apollo"
    "find-secrets"
    "resource-policies"
    "org-policies"          # CORRECTED: was "get-orgpolicies"
    "ecr-dump"
    "cdk-bucket-takeover"
    "cloudfront-s3-takeover"
    "get-console"
    "apollo-offline"
    "ec2-screenshot-analysis"
    "public-resources-single"
    "find-secrets-resource"
    "ip-lookup"
    "access-key-to-account-id"
    "known-account-id"
    "apollo-query"
    "expand-actions"
)

echo "=== Nebula vs aurelian Output Comparison ==="
echo ""

PASS=0
FAIL=0
SKIP=0

for cmd in "${COMMANDS[@]}"; do
    nebula_file="$NEBULA_OUT/${cmd}.json"
    aurelian_file="$aurelian_OUT/${cmd}.json"

    if [[ ! -f "$nebula_file" ]] || [[ ! -f "$aurelian_file" ]]; then
        echo "SKIP: $cmd - missing output file(s)"
        ((SKIP++))
        continue
    fi

    # Normalize both files
    normalize_json "$nebula_file" "/tmp/nebula_norm.json"
    normalize_json "$aurelian_file" "/tmp/aurelian_norm.json"

    # Compare
    if diff -q "/tmp/nebula_norm.json" "/tmp/aurelian_norm.json" > /dev/null 2>&1; then
        echo "PASS: $cmd"
        ((PASS++))
    else
        echo "FAIL: $cmd"
        diff "/tmp/nebula_norm.json" "/tmp/aurelian_norm.json" > "$DIFF_OUT/${cmd}.diff"
        echo "  -> Diff saved to: $DIFF_OUT/${cmd}.diff"
        ((FAIL++))
    fi
done

echo ""
echo "=== Summary ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "SKIP: $SKIP"
echo "TOTAL: $((PASS + FAIL + SKIP))"
```

### 4.3 Deep Comparison (Structural)

For commands that fail simple JSON diff, use structural comparison:

```bash
#!/bin/bash
# deep_compare.sh - Structural comparison for complex outputs

deep_compare() {
    local cmd="$1"
    local nebula_file="$NEBULA_OUT/${cmd}.json"
    local aurelian_file="$aurelian_OUT/${cmd}.json"

    echo "=== Deep Comparison: $cmd ==="

    # Compare top-level keys
    echo "Top-level keys (nebula):"
    jq -r 'keys[]' "$nebula_file" | sort

    echo "Top-level keys (aurelian):"
    jq -r 'keys[]' "$aurelian_file" | sort

    # Compare record counts
    echo "Record counts:"
    echo "  Nebula: $(jq 'if type == "array" then length else 1 end' "$nebula_file")"
    echo "  aurelian: $(jq 'if type == "array" then length else 1 end' "$aurelian_file")"

    # Compare data types
    echo "Schema comparison:"
    jq 'paths(scalars) | map(tostring) | join(".")' "$nebula_file" | sort | uniq > /tmp/nebula_schema
    jq 'paths(scalars) | map(tostring) | join(".")' "$aurelian_file" | sort | uniq > /tmp/aurelian_schema
    diff /tmp/nebula_schema /tmp/aurelian_schema || true
}
```

---

## 5. Flag Compatibility Matrix

### 5.1 Global Flags Comparison

| Flag | Nebula | aurelian | Notes |
|------|--------|------------|-------|
| `--log-level` | ✓ | ✓ | Same |
| `--quiet` | ✓ | ✓ | Same |
| `--no-color` | ✓ | ✓ | Same |
| `--output` | ✓ (dir) | N/A | Different approach |
| `--outfile` | ✓ | N/A | Different approach |
| `--output-format` | N/A | ✓ (json/markdown/default) | Different approach |
| `--indent` | ✓ | N/A | Nebula only |

### 5.2 AWS-Specific Flags Comparison

| Flag | Nebula | aurelian | Notes |
|------|--------|------------|-------|
| `-r, --regions` | ✓ | ✓ | Same |
| `-t, --resource-type` | ✓ | ✓ | Same |
| `-p, --profile` | ✓ | ✓ | Same |
| `--profile-dir` | ✓ | ✓ | Same |
| `--cache-dir` | ✓ | ✓ | Same |
| `--cache-ttl` | ✓ | ✓ | Same |
| `--cache-ext` | ✓ | ✓ | Same |
| `--disable-cache` | ✓ | ✓ | Same |
| `--cache-error-resp` | ✓ | ✓ | Same |
| `--cache-error-resp-type` | ✓ | ✓ | Same |
| `--opsec_level` | ✓ | ✓ | Same |
| `--aws-cache-log-level` | ✓ | ✓ | Same |
| `--aws-cache-log-file` | ✓ | ✓ | Same |

---

## 6. Chain Input Commands (Important)

Several commands use **chain input parameters** instead of direct CLI flags. These commands are designed to receive data from upstream modules in a processing chain.

### 6.1 Chain Input Commands

| Command | Chain Input Parameter | Standalone Behavior |
|---------|----------------------|---------------------|
| `apollo` | `resource-type` | May error or use defaults |
| `resource-policies` | `resource-type` | May enumerate all supported types |
| `public-resources` | `resource-type` | Has `-p` flag, resource-type from chain |

### 6.2 Testing Chain Commands

When testing these commands standalone:

1. **Document actual behavior** - Run and record what happens
2. **Compare error handling** - Both tools should fail similarly if chain input is required
3. **Test with chains** - For accurate comparison, test as part of a chain:

```bash
# Example chain: list resources, then analyze with apollo
./modules/nebula/nebula aws recon list -t AWS::IAM::Role | ./modules/nebula/nebula aws recon apollo

# Or use built-in chain syntax if supported
./modules/nebula/nebula chain "list -t AWS::IAM::Role -> apollo"
```

### 6.3 Commands with Optional Chain Input

Some commands accept chain input but also have fallback behavior:

| Command | Without Chain Input | With Chain Input |
|---------|---------------------|------------------|
| `apollo-offline` | Uses files from `-g`, `-o`, `-rp` flags | Combines chain data with files |
| `find-secrets` | Scans all supported types | Scans specific resource types |
| `ecr-dump` | Scans default ECR types | Scans specified types |

---

## 7. Test Execution Order

### 7.1 Recommended Execution Sequence

1. **Build Both Tools** (5 min)
   - Compile nebula and aurelian binaries
   - Verify versions

2. **Setup Test Environment** (5 min)
   - Create output directories
   - Configure AWS credentials
   - Set test parameters

3. **Phase 1: Auto-Run Commands** (10 min)
   - Execute 8 auto-run commands
   - No input parameters required

4. **Phase 2: Resource Commands** (15 min)
   - Execute region/resource-type dependent commands
   - Use standardized test parameters

5. **Phase 3: Analyze Commands** (10 min)
   - Execute analysis commands with test inputs

6. **Phase 4: Special Commands** (10 min)
   - Execute commands requiring special setup
   - Skip if prerequisites missing

7. **Output Comparison** (15 min)
   - Run normalization
   - Execute comparison scripts
   - Generate diff reports

8. **Report Generation** (5 min)
   - Compile results
   - Document discrepancies

---

## 8. Expected Differences

### 7.1 Command Names

All command names are identical between nebula and aurelian. No mapping required.

### 7.2 Expected Output Differences

These fields should be excluded from comparison:

- `timestamp` / `execution_time` - Timing data
- `request_id` / `trace_id` - Request identifiers
- `cache_hit` - Cache status (varies by run order)
- `version` - Tool version strings
- File paths containing tool name (`nebula-output` vs `aurelian-output`)

### 7.3 Structural Differences to Investigate

- Output file naming conventions
- JSON structure (array vs object wrapping)
- Error message formatting
- Progress indicator output

---

## 9. Success Criteria

### 8.1 Pass Criteria

A command comparison **PASSES** if:

1. Both commands execute without error
2. Normalized JSON outputs are identical
3. OR structural comparison shows:
   - Same data content
   - Same record counts
   - Differences only in metadata fields

### 8.2 Fail Criteria

A command comparison **FAILS** if:

1. One tool errors while other succeeds
2. Data content differs (resources, findings, etc.)
3. Record counts differ
4. Schema structure differs unexpectedly

### 8.3 Overall Success

The comparison suite **PASSES** if:
- ≥95% of commands pass
- All failures are documented with root cause
- No data integrity differences found

---

## 10. Troubleshooting Guide

### 9.1 Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Missing output file | Command failed silently | Check command logs, add `--log-level debug` |
| Different record counts | Pagination differences | Verify both tools hit same APIs |
| Schema mismatch | Output format evolution | Document as known difference |
| Cache inconsistency | Different cache states | Run with `--disable-cache` |

### 9.2 Debug Commands

```bash
# Run with verbose logging
./modules/nebula/nebula aws recon whoami --log-level debug 2>&1 | tee debug.log

# Disable caching for clean comparison
./modules/nebula/nebula aws recon list --disable-cache --resource-type AWS::S3::Bucket

# Check tool versions
./modules/nebula/nebula --version
./modules/aurelian/aurelian version
```

---

## 11. Master Test Script

```bash
#!/bin/bash
# run_comparison.sh - Master test script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Configuration
export NEBULA_OUT="$REPO_ROOT/comparison-tests/nebula"
export aurelian_OUT="$REPO_ROOT/comparison-tests/aurelian"
export DIFF_OUT="$REPO_ROOT/comparison-tests/diffs"

# Test parameters
export TEST_REGIONS="${TEST_REGIONS:-us-east-1}"
export TEST_RESOURCE_TYPE="${TEST_RESOURCE_TYPE:-AWS::S3::Bucket}"
export AWS_PROFILE="${AWS_PROFILE:-default}"

echo "=== Nebula vs aurelian AWS Comparison Suite ==="
echo "Regions: $TEST_REGIONS"
echo "Resource Type: $TEST_RESOURCE_TYPE"
echo "AWS Profile: $AWS_PROFILE"
echo ""

# Step 1: Setup
echo "Step 1: Setting up test environment..."
mkdir -p "$NEBULA_OUT" "$aurelian_OUT" "$DIFF_OUT"

# Step 2: Build
echo "Step 2: Building tools..."
(cd "$REPO_ROOT/modules/nebula" && go build -o nebula .)
(cd "$REPO_ROOT/modules/aurelian" && go build -o aurelian .)

# Step 3: Verify AWS credentials
echo "Step 3: Verifying AWS credentials..."
aws sts get-caller-identity --profile "$AWS_PROFILE" || {
    echo "ERROR: AWS credentials not configured"
    exit 1
}

# Step 4: Run tests (phases 1-4)
echo "Step 4: Running comparison tests..."
# ... (execute phase scripts)

# Step 5: Compare outputs
echo "Step 5: Comparing outputs..."
# ... (execute comparison scripts)

# Step 6: Generate report
echo "Step 6: Generating comparison report..."
cat > "$REPO_ROOT/comparison-tests/REPORT.md" << EOF
# Nebula vs aurelian Comparison Report

**Date**: $(date -Iseconds)
**Regions Tested**: $TEST_REGIONS
**Resource Type**: $TEST_RESOURCE_TYPE

## Results

$(cat comparison-tests/results.txt)

## Differences

$(ls -la comparison-tests/diffs/)
EOF

echo ""
echo "=== Comparison Complete ==="
echo "Report: $REPO_ROOT/comparison-tests/REPORT.md"
```

---

## 12. Next Steps

1. **Review this plan** - Validate command mappings and test parameters
2. **Create test data** - Prepare any required input files (GAAD, org policies)
3. **Execute Phase 1** - Start with auto-run commands
4. **Iterate** - Address failures, update normalization rules
5. **Document** - Record all known differences and their justifications
