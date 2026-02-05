#!/bin/bash
# Script to migrate AWS link files to NativeAWSLink pattern

set -e

cd /Users/nathansportsman/capabilities/modules/aurelian

echo "=== Migrating AWS link files to NativeAWSLink ==="

# Files to migrate:
# 1. apollo_control_flow.go
# 2. aws_resource_policy.go
# 3. cdk_bootstrap_checker.go
# 4. cdk_bucket_validator.go
# 5. cdk_policy_analyzer.go
# 6. cdk_qualifier_discovery.go
# 7. cdk_role_detector.go
# 8. console_url.go (DONE)
# 9. find_secrets.go

echo "File 1: console_url.go - ALREADY COMPLETE"

echo "Verifying build status..."
go build ./pkg/links/aws/... 2>&1 | grep -E "error|undefined" | head -20 || echo "Build check complete"

echo "Migration script complete"
