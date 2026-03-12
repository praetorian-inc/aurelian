package extraction

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func TestExtractIaC_TemplateSpec_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.resources/templatespecs")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.resources/templatespecs")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "template-spec-versions")
}

func TestExtractIaC_Blueprint_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.blueprint/blueprints")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.blueprint/blueprints")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "blueprint-artifacts")
}

func TestExtractIaC_Policy_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.authorization/policydefinitions")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.authorization/policydefinitions")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "policy-definitions")
}

func TestExtractPolicyDefinitions_SubscriptionScopeIDParsing(t *testing.T) {
	// Verify that extractPolicyDefinitions correctly extracts the policy name
	// from a subscription-scope resource ID (no resource group in path).
	// The function previously used ParseAzureResourceID which fails for these IDs.
	// Now it uses strings.Split to get the last path segment.
	//
	// We test indirectly: calling the extractor with a nil credential will fail at
	// the ARM API call, but ONLY if the ID parsing step succeeded. If ID parsing
	// fails, the function returns an ID parsing error before reaching the API call.

	ctx := extractContext{
		Context: context.Background(),
		Cred:    nil, // nil cred causes ARM client creation to succeed but API call to fail
	}

	// Subscription-scope ID (no resource group): this is what the ARM enumerator emits
	subscriptionScopeID := "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyDefinitions/my-custom-policy"

	r := output.NewAzureResource("00000000-0000-0000-0000-000000000000", "Microsoft.Authorization/policyDefinitions", subscriptionScopeID)

	out := pipeline.New[output.ScanInput]()
	var gotErr error
	go func() {
		defer out.Close()
		gotErr = extractPolicyDefinitions(ctx, r, out)
	}()
	out.Drain() // consume and discard

	// The error (if any) should NOT be "invalid Azure resource ID" or "too few segments"
	// It may be an ARM API error (nil cred), but not a parsing error.
	if gotErr != nil {
		assert.NotContains(t, gotErr.Error(), "invalid Azure resource ID",
			"should not fail with ID parsing error for subscription-scope IDs")
		assert.NotContains(t, gotErr.Error(), "too few segments",
			"should not fail with ID parsing error for subscription-scope IDs")
	}
}
