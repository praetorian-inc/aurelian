package resourcetypes

// exclusions are types that a consumer module may declare in
// SupportedResourceTypes() but that list-all must NOT enumerate. Each entry
// requires a justification documenting why the type is excluded.
//
// Adding an entry: include the resource type as the key and a one-sentence
// justification as the value. The justification is asserted non-empty by
// TestExclusions_HaveJustifications.
//
// Removing an entry: ensure no consumer module relies on the exclusion to
// suppress a type it declares unnecessarily.
var exclusions = map[string]string{
	"AWS::Organizations::Account": "Pseudo-input used by Guard to pass account context to modules; enumerating it would discover sibling accounts in the org rather than resources within the current account.",
}

// IsExcluded reports whether a resource type is on the exclusion list.
func IsExcluded(rt string) bool {
	_, ok := exclusions[rt]
	return ok
}
