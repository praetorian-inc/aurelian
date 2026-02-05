#!/bin/bash

echo "=== GCP Links Migration Verification ==="
echo ""

echo "1. Completed files:"
ls -la pkg/links/gcp/hierarchy/organization.go.bak 2>/dev/null && echo "   ✅ organization.go (backup exists)" || echo "   ❌ No backup found"
grep -q "janus-framework" pkg/links/gcp/hierarchy/organization.go 2>/dev/null && echo "   ❌ Still has Janus imports!" || echo "   ✅ No Janus imports"
echo ""

echo "2. Remaining Janus imports:"
count=$(grep -r "janus-framework" pkg/links/gcp/ --include="*.go" 2>/dev/null | wc -l | tr -d ' ')
echo "   Count: $count (target: 0)"
echo ""

echo "3. Files to migrate:"
find pkg/links/gcp -name "*.go" -not -name "*_test.go" -not -name "*_migrated.go" -not -name "*.bak" -not -name "native_base.go" | sort
echo ""

echo "4. Exit criteria status:"
echo "   [ ] All 13 files migrated/deleted"
echo "   [ ] Zero janus-framework imports"
echo "   [ ] go build succeeds"
echo "   [ ] All tests pass"
echo ""

echo "5. Next file to migrate:"
echo "   pkg/links/gcp/hierarchy/folders.go"
