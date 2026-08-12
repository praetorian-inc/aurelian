// Package output_test exercises AWSEnabledRegions from outside the package:
// Guard consumes this type from a separate Go module and can therefore reach
// only exported identifiers, which is why RegionSource is exported here.
package output_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pins the VALUE the constructor returns, reached through exported identifiers
// only; aws_regions.go's own compile-time assertion covers the pointer form.
var _ model.AurelianModel = output.NewAWSEnabledRegions(nil, output.SourceEC2API)

// marshalKeys marshals v and returns its top-level JSON object keys.
func marshalKeys(t *testing.T, v any) ([]string, string) {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err, "marshalling must not fail")

	var generic map[string]any
	require.NoError(t, json.Unmarshal(raw, &generic), "output must be a JSON object")

	keys := make([]string, 0, len(generic))
	for k := range generic {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys, string(raw)
}

func TestAWSEnabledRegions_MarshalsExactlyThreeFields(t *testing.T) {
	m := output.NewAWSEnabledRegions(
		[]string{"us-east-1", "us-west-2"},
		output.SourceAccountAPI,
	)

	keys, raw := marshalKeys(t, m)

	assert.Equal(t, []string{"count", "regions", "source"}, keys,
		"AWSEnabledRegions must marshal exactly three fields; got %s", raw)
}

func TestAWSEnabledRegions_EmbeddedModelAddsNoFields(t *testing.T) {
	m := output.NewAWSEnabledRegions([]string{"eu-west-1"}, output.SourceEC2API)

	_, raw := marshalKeys(t, m)

	assert.NotContains(t, raw, "BaseAurelianModel",
		"the sealing token must not appear on the wire")
	assert.NotContains(t, raw, "IsAurelianModel")
}

// CallerIdentity in this same package already emits a full ARN and account ID.
// AWSEnabledRegions must emit strictly less.
func TestAWSEnabledRegions_LeaksNoIdentityOrPaths(t *testing.T) {
	m := output.NewAWSEnabledRegions(
		[]string{"us-east-1", "us-gov-west-1"},
		output.SourceStaticFallback,
	)

	keys, raw := marshalKeys(t, m)

	// Matched as a substring of each lowercased key. Handing assert.NotContains
	// a []string haystack would make it element-equality, rejecting only a key
	// spelled exactly "account" and letting accountId, arnValue and profileName
	// past a guard meant to keep identity material off the wire.
	forbiddenTokens := []string{
		"account", "arn", "profile",
		"path", "credentials", "identity", "user",
	}

	// Non-vacuity guard: an empty key set would make the loop below assert
	// nothing while still reporting green.
	require.NotEmpty(t, keys, "precondition: the model must marshal some keys")

	for _, key := range keys {
		lower := strings.ToLower(key)
		for _, forbidden := range forbiddenTokens {
			assert.NotContains(t, lower, forbidden,
				"key %q contains forbidden token %q; AWSEnabledRegions must "+
					"carry no identity material", key, forbidden)
		}
	}

	// Region names and RegionSource values contain no path separator, so any
	// "/" in the payload means a filesystem path or an ARN leaked in.
	assert.NotContains(t, raw, "/",
		"payload must contain no path separator (no filesystem path, no ARN): %s", raw)
	assert.NotContains(t, raw, `"arn:`, "payload must contain no ARN")

	assert.NotRegexp(t, `\b\d{12}\b`, raw, "payload must contain no AWS account ID")
}

// Proves the de-escalation claim is real rather than asserted: the sibling type
// in this same package DOES carry identity material, and ours does not.
func TestAWSEnabledRegions_IsDeEscalationRelativeToCallerIdentity(t *testing.T) {
	ci := output.CallerIdentity{
		Status:  "success",
		ARN:     "arn:aws:iam::123456789012:user/alice",
		Account: "123456789012",
	}
	ciKeys, ciRaw := marshalKeys(t, ci)

	require.Contains(t, ciKeys, "arn", "precondition: CallerIdentity emits an ARN")
	require.Contains(t, ciKeys, "account", "precondition: CallerIdentity emits an account")
	require.Contains(t, ciRaw, "123456789012")

	regionKeys, _ := marshalKeys(t,
		output.NewAWSEnabledRegions([]string{"us-east-1"}, output.SourceAccountAPI))

	for _, k := range regionKeys {
		assert.NotContains(t, []string{"arn", "account"}, k,
			"AWSEnabledRegions must not reintroduce identity fields")
	}
}

// Count is an invariant of construction, not a caller obligation.
func TestNewAWSEnabledRegions_CountMatchesRegions(t *testing.T) {
	tests := []struct {
		name    string
		regions []string
	}{
		{name: "empty", regions: []string{}},
		{name: "nil", regions: nil},
		{name: "single", regions: []string{"us-east-1"}},
		{name: "many", regions: []string{"us-east-1", "us-west-2", "eu-west-1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := output.NewAWSEnabledRegions(tt.regions, output.SourceEC2API)

			assert.Equal(t, len(m.Regions), m.Count,
				"Count must equal len(Regions)")
			assert.Len(t, tt.regions, m.Count)
		})
	}
}

// The constructor must copy its input so a caller that later sorts or mutates
// the model cannot reach back into the slice it was handed. This matters
// because the tier-3 source is a package-level variable.
func TestNewAWSEnabledRegions_DoesNotAliasCallerSlice(t *testing.T) {
	caller := []string{"us-west-2", "us-east-1"}
	original := append([]string(nil), caller...)

	m := output.NewAWSEnabledRegions(caller, output.SourceStaticFallback)

	sort.Strings(m.Regions)
	assert.Equal(t, original, caller,
		"constructing the model must not alias the caller's backing array")

	caller[0] = "MUTATED"
	assert.NotContains(t, m.Regions, "MUTATED",
		"model must hold its own copy")
}

// The three source values are the wire contract Guard matches on. Pinning the
// literal strings makes any rename a deliberate, breaking change.
func TestRegionSource_WireValues(t *testing.T) {
	assert.Equal(t, "account-api", string(output.SourceAccountAPI))
	assert.Equal(t, "ec2-api", string(output.SourceEC2API))
	assert.Equal(t, "static-fallback", string(output.SourceStaticFallback))
}

func TestAWSEnabledRegions_SourceSerialisesAsPlainString(t *testing.T) {
	m := output.NewAWSEnabledRegions([]string{"us-east-1"}, output.SourceStaticFallback)

	raw, err := json.Marshal(m)
	require.NoError(t, err)

	assert.Contains(t, string(raw), `"source":"static-fallback"`,
		"source must serialise as a bare string")
}
