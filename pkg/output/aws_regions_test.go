// Package output_test exercises AWSEnabledRegions from OUTSIDE the package.
//
// The external test package is deliberate: Guard consumes this type from a
// separate Go module and can therefore only reach exported identifiers. Testing
// from `output_test` proves the wire contract is constructible without any
// package-internal access, which is the whole reason RegionSource is exported
// here rather than declared in internal/helpers/aws.
package output_test

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Pins what production's own assertion does not: that the VALUE the constructor
// returns satisfies the sealed marker interface, reached through exported
// identifiers only — the wire contract this file's header exists to prove. The
// pointer form is already pinned by aws_regions.go's compile-time assertion.
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

// SAC-7: the marshalled object exposes exactly regions, count, source.
func TestAWSEnabledRegions_MarshalsExactlyThreeFields(t *testing.T) {
	m := output.NewAWSEnabledRegions(
		[]string{"us-east-1", "us-west-2"},
		output.SourceAccountAPI,
	)

	keys, raw := marshalKeys(t, m)

	assert.Equal(t, []string{"count", "regions", "source"}, keys,
		"AWSEnabledRegions must marshal exactly three fields; got %s", raw)
}

// SAC-7: the embedded marker type must contribute no wire fields.
func TestAWSEnabledRegions_EmbeddedModelAddsNoFields(t *testing.T) {
	m := output.NewAWSEnabledRegions([]string{"eu-west-1"}, output.SourceEC2API)

	_, raw := marshalKeys(t, m)

	assert.NotContains(t, raw, "BaseAurelianModel",
		"the sealing token must not appear on the wire")
	assert.NotContains(t, raw, "IsAurelianModel")
}

// SAC-7: no identity material and no filesystem paths may appear.
//
// This is the de-escalation assertion. CallerIdentity (same package) already
// emits a full ARN and account ID; AWSEnabledRegions must emit strictly less.
func TestAWSEnabledRegions_LeaksNoIdentityOrPaths(t *testing.T) {
	m := output.NewAWSEnabledRegions(
		[]string{"us-east-1", "us-gov-west-1"},
		output.SourceStaticFallback,
	)

	keys, raw := marshalKeys(t, m)

	for _, forbidden := range []string{
		"account", "arn", "profile", "profileDir", "profile_dir",
		"path", "credentials", "identity", "user",
	} {
		assert.NotContains(t, keys, forbidden,
			"field %q must never appear in AWSEnabledRegions", forbidden)
	}

	// Region names and RegionSource values contain no path separator, so any
	// "/" in the payload means a filesystem path or an ARN leaked in.
	assert.NotContains(t, raw, "/",
		"payload must contain no path separator (no filesystem path, no ARN): %s", raw)
	assert.NotContains(t, raw, `"arn:`, "payload must contain no ARN")

	// Guard against an account ID leaking as a bare 12-digit string.
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

// SAC-7: Count is an invariant of construction, not a caller obligation.
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

	// Mutating the model must not disturb the caller's slice.
	sort.Strings(m.Regions)
	assert.Equal(t, original, caller,
		"constructing the model must not alias the caller's backing array")

	// And mutating the caller's slice must not disturb the model.
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
