#!/bin/bash
# Test all AWS modules with JSON output

set -e

aurelian="./aurelian"
OUTPUT_FORMAT="--output-format json"

echo "Testing aurelian AWS Modules"
echo "================================"

# Quick/Safe modules (fast to run)
QUICK_MODULES=(
    "aws recon whoami"
    "aws recon summary"
    "aws analyze access-key-to-account-id"
)

# Resource enumeration modules
RECON_MODULES=(
    "aws recon list -t AWS::S3::Bucket"
    "aws recon list -t AWS::IAM::Role"
    "aws recon account-auth-details"
    "aws recon resource-policies"
    "aws recon org-policies"
)

# Security analysis modules
ANALYSIS_MODULES=(
    "aws recon public-resources"
    "aws recon cdk-bucket-takeover"
    "aws recon cloudfront-s3-takeover"
)

test_module() {
    local cmd=$1
    echo -n "Testing: $cmd ... "

    if $aurelian $cmd $OUTPUT_FORMAT 2>/dev/null >/dev/null; then
        echo "✅ PASS"
        return 0
    else
        exit_code=$?
        echo "❌ FAIL (exit $exit_code)"
        return 1
    fi
}

echo ""
echo "Quick Modules:"
echo "-------------"
for module in "${QUICK_MODULES[@]}"; do
    test_module "$module"
done

echo ""
echo "Recon Modules:"
echo "-------------"
for module in "${RECON_MODULES[@]}"; do
    test_module "$module"
done

echo ""
echo "Analysis Modules:"
echo "----------------"
for module in "${ANALYSIS_MODULES[@]}"; do
    test_module "$module"
done

echo ""
echo "================================"
echo "Test suite complete"
