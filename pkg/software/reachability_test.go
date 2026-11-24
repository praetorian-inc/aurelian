package software_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/loader" // populate the type registry
	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A decoder nothing enumerates is dead code that looks like coverage. Detect
// returns technologies for a resource type, but only types in GetAll() are ever
// listed, so a decoder for a type outside that union never sees a resource and
// never emits — while the registry, the unit tests and the type list all read as
// though the service were covered.
//
// This shipped: AWS::MSK::Cluster and AWS::ElastiCache::CacheCluster had working
// decoders and were enumerated by nothing. The integration test could not catch
// it, because it passes resource-type explicitly and so proves only that a
// decoder works when something hands it a resource.
//
// The fix for a failure here is a judgement call, not a mechanical one. Adding
// the type to baseline costs one ListResources call per region, per account, on
// every list-all run, for every customer. If that is not worth paying, the
// honest fix is deleting the decoder, not leaving it unreachable.
func TestEveryDecodedTypeIsEnumerated(t *testing.T) {
	all := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		all[rt] = true
	}
	// Guards against the loader import being stripped, which would collapse
	// GetAll() to baseline and make this test pass by observing less.
	require.Contains(t, all, "AWS::Route53::HostedZone",
		"loader blank-import appears stripped; GetAll() is no longer the real union")

	registered := software.RegisteredTypes()
	require.NotEmpty(t, registered, "no decoders registered; the check would be vacuous")

	for _, rt := range registered {
		assert.True(t, all[rt],
			"software decodes %q but list-all enumerates no such type, so the decoder "+
				"can never fire. Either add %q to baseline in pkg/aws/resourcetypes/types.go "+
				"(and classify its service in reviewedRegionalServices) or delete the decoder.",
			rt, rt)
	}
}
