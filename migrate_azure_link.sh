#!/bin/bash
# Migration script for Azure links from Janus to native plugin

set -e

FILE="$1"

if [ -z "$FILE" ]; then
    echo "Usage: $0 <file.go>"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "File not found: $FILE"
    exit 1
fi

# Backup original
cp "$FILE" "$FILE.backup"

# Step 1: Replace imports
sed -i '' 's|"github.com/praetorian-inc/janus-framework/pkg/chain"|"context"\
\
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"\
	"github.com/praetorian-inc/aurelian/pkg/plugin"|g' "$FILE"

sed -i '' '/janus-framework.*chain\/cfg/d' "$FILE"
sed -i '' '/janus-framework.*types/d' "$FILE"

# Step 2: Replace chain.Base with base.NativeAzureLink
sed -i '' 's|\*chain\.Base|\*base.NativeAzureLink|g' "$FILE"

# Step 3: Replace constructor pattern (this is complex, needs manual intervention)
echo "⚠️  Manual step required for $FILE:"
echo "  - Update constructor to: func NewXxx(args map[string]any) *Xxx"
echo "  - Add: return &Xxx{NativeAzureLink: base.NewNativeAzureLink(\"xxx\", args)}"
echo "  - Add init() with plugin.Register()"

echo "✅ Basic replacements complete for: $FILE"
echo "💡 Next: Manually verify and complete migration"
