package extraction

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func ptrTo(s string) *string { return &s }

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

// TestPolicyDefinitionProperties_MarshalComplexStructures verifies that
// json.Marshal handles the varied policy rule structures found in production
// tenants. The extraction path does json.Marshal(result.Properties) and if
// the SDK returns a structure with unexpected fields, marshalling could fail.
func TestPolicyDefinitionProperties_MarshalComplexStructures(t *testing.T) {
	policyType := armpolicy.PolicyTypeCustom

	tests := []struct {
		name string
		prop *armpolicy.DefinitionProperties
	}{
		{
			name: "simple audit rule",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("Simple Audit"),
				PolicyRule: map[string]any{
					"if":   map[string]any{"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
					"then": map[string]any{"effect": "audit"},
				},
			},
		},
		{
			name: "deeply nested allOf/anyOf conditions",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("Complex Nested"),
				PolicyRule: map[string]any{
					"if": map[string]any{
						"allOf": []any{
							map[string]any{"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
							map[string]any{
								"anyOf": []any{
									map[string]any{"field": "Microsoft.Storage/storageAccounts/networkAcls.defaultAction", "equals": "Allow"},
									map[string]any{
										"allOf": []any{
											map[string]any{"field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "equals": "false"},
											map[string]any{"field": "Microsoft.Storage/storageAccounts/minimumTlsVersion", "notEquals": "TLS1_2"},
										},
									},
								},
							},
						},
					},
					"then": map[string]any{"effect": "deny"},
				},
			},
		},
		{
			name: "policy with parameters and metadata",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("Parameterized Policy"),
				Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
					"effect": {
						DefaultValue: "Audit",
						AllowedValues: []any{"Audit", "Deny", "Disabled"},
						Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
							DisplayName: ptrTo("Effect"),
							Description: ptrTo("Enable or disable the policy"),
						},
					},
					"listOfAllowedLocations": {
						Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
							DisplayName:  ptrTo("Allowed Locations"),
							Description:  ptrTo("The list of allowed locations"),
							StrongType:   ptrTo("location"),
						},
					},
				},
				PolicyRule: map[string]any{
					"if":   map[string]any{"not": map[string]any{"field": "location", "in": "[parameters('listOfAllowedLocations')]"}},
					"then": map[string]any{"effect": "[parameters('effect')]"},
				},
				Metadata: map[string]any{
					"category":    "General",
					"version":     "2.0.0",
					"preview":     true,
					"deprecated":  false,
					"portalReview": "done",
					"nestedObj":   map[string]any{"key1": "val1", "key2": []string{"a", "b", "c"}},
				},
			},
		},
		{
			name: "policy with deployIfNotExists effect",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("DeployIfNotExists"),
				PolicyRule: map[string]any{
					"if": map[string]any{"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
					"then": map[string]any{
						"effect": "DeployIfNotExists",
						"details": map[string]any{
							"type":              "Microsoft.Compute/virtualMachines/extensions",
							"roleDefinitionIds": []string{"/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"},
							"existenceCondition": map[string]any{
								"allOf": []any{
									map[string]any{"field": "Microsoft.Compute/virtualMachines/extensions/type", "equals": "MDE.Linux"},
									map[string]any{"field": "Microsoft.Compute/virtualMachines/extensions/provisioningState", "equals": "Succeeded"},
								},
							},
							"deployment": map[string]any{
								"properties": map[string]any{
									"mode":     "incremental",
									"template": map[string]any{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "nil properties",
			prop: nil,
		},
		{
			name: "empty policy rule",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("Empty Rule"),
				PolicyRule:  nil,
			},
		},
		{
			name: "policy with secret in metadata",
			prop: &armpolicy.DefinitionProperties{
				PolicyType:  &policyType,
				DisplayName: ptrTo("Secret Metadata"),
				Metadata: map[string]any{
					"connection_string": "Server=myserver;Database=mydb;User Id=admin;Password=SuperSecret123!",
					"api_key":           "AKIAIOSFODNN7EXAMPLE",
				},
				PolicyRule: map[string]any{
					"if":   map[string]any{"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
					"then": map[string]any{"effect": "audit"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prop == nil {
				return // nil properties are handled by the caller
			}
			data, err := json.Marshal(tt.prop)
			require.NoError(t, err, "json.Marshal should not fail for policy properties")
			assert.NotEmpty(t, data)

			// Verify round-trip: unmarshal back and re-marshal
			var roundTrip armpolicy.DefinitionProperties
			require.NoError(t, json.Unmarshal(data, &roundTrip))
			data2, err := json.Marshal(&roundTrip)
			require.NoError(t, err, "re-marshal after round-trip should not fail")
			assert.NotEmpty(t, data2)
		})
	}
}

// TestPolicyDefinition_UnmarshalRawJSON tests that the Azure SDK struct
// can handle raw JSON payloads that mimic real API responses, including
// edge cases that could cause deserialization failures in production.
func TestPolicyDefinition_UnmarshalRawJSON(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		expectErr bool
	}{
		{
			name: "standard custom policy",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/my-policy",
				"name": "my-policy",
				"type": "Microsoft.Authorization/policyDefinitions",
				"properties": {
					"policyType": "Custom",
					"mode": "All",
					"displayName": "Test Policy",
					"policyRule": {"if":{"field":"type","equals":"Microsoft.Compute/virtualMachines"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with unknown top-level field",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p1",
				"name": "p1",
				"type": "Microsoft.Authorization/policyDefinitions",
				"systemData": {"createdBy": "admin@contoso.com", "createdAt": "2024-01-01T00:00:00Z"},
				"properties": {
					"policyType": "Custom",
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with unknown property field (version — newer API)",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p2",
				"name": "p2",
				"properties": {
					"policyType": "Custom",
					"version": "2.1.0",
					"versions": ["2.1.0", "2.0.0", "1.0.0"],
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with deeply nested metadata containing arrays of objects",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p3",
				"name": "p3",
				"properties": {
					"policyType": "Custom",
					"metadata": {
						"category": "Security",
						"version": "3.0.0",
						"preview": true,
						"deprecated": false,
						"requiredProviders": ["Microsoft.Compute", "Microsoft.Network"],
						"parameterScopes": {"effect": "/providers/Microsoft.Authorization"},
						"alzCloudEnvironments": ["AzureCloud", "AzureChinaCloud"],
						"source": "https://github.com/Azure/Enterprise-Scale/",
						"portalReview": "2024-01-01",
						"nestedDeep": {"level1": {"level2": {"level3": {"level4": "value"}}}}
					},
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with all parameter types",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p4",
				"name": "p4",
				"properties": {
					"policyType": "Custom",
					"parameters": {
						"stringParam": {"type": "String", "defaultValue": "hello", "metadata": {"displayName": "String"}},
						"intParam": {"type": "Integer", "defaultValue": 42, "metadata": {"displayName": "Int"}},
						"boolParam": {"type": "Boolean", "defaultValue": true},
						"arrayParam": {"type": "Array", "defaultValue": ["a", "b", "c"]},
						"objectParam": {"type": "Object", "defaultValue": {"key": "value", "nested": {"deep": true}}}
					},
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"[parameters('stringParam')]"}}
				}
			}`,
		},
		{
			name: "policy with DeployIfNotExists and roleDefinitionIds",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p5",
				"name": "p5",
				"properties": {
					"policyType": "Custom",
					"policyRule": {
						"if": {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
						"then": {
							"effect": "DeployIfNotExists",
							"details": {
								"type": "Microsoft.Compute/virtualMachines/extensions",
								"roleDefinitionIds": [
									"/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
									"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
								],
								"existenceCondition": {
									"allOf": [
										{"field": "Microsoft.Compute/virtualMachines/extensions/type", "equals": "MDE.Linux"},
										{"field": "Microsoft.Compute/virtualMachines/extensions/provisioningState", "in": ["Succeeded", "Updating"]}
									]
								},
								"deployment": {
									"properties": {
										"mode": "incremental",
										"template": {
											"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
											"contentVersion": "1.0.0.0",
											"parameters": {"vmName": {"type": "string"}},
											"resources": [{"type": "Microsoft.Compute/virtualMachines/extensions", "apiVersion": "2023-03-01"}]
										}
									}
								}
							}
						}
					}
				}
			}`,
		},
		{
			name: "policy with null fields",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p6",
				"name": "p6",
				"properties": {
					"policyType": "Custom",
					"displayName": null,
					"description": null,
					"metadata": null,
					"parameters": null,
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with unicode and special characters",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p7",
				"name": "p7",
				"properties": {
					"policyType": "Custom",
					"displayName": "策略定义 — ポリシー — Richtlinie — سياسة",
					"description": "Contains emoji 🔒 and special chars: <>&\"' \t\n\\",
					"metadata": {"category": "Sécurité", "注释": "测试用"},
					"policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}
				}
			}`,
		},
		{
			name: "policy with empty properties object",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p8",
				"name": "p8",
				"properties": {}
			}`,
		},
		{
			name: "policy with very large policyRule (100+ conditions)",
			json: func() string {
				// Build a policy rule with 100 nested allOf conditions
				conditions := make([]string, 100)
				for i := range conditions {
					conditions[i] = `{"field":"tags.tag` + json.Number(fmt.Sprintf("%d", i)).String() + `","exists":"true"}`
				}
				return `{
					"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/p9",
					"name": "p9",
					"properties": {
						"policyType": "Custom",
						"policyRule": {
							"if": {"allOf": [` + strings.Join(conditions, ",") + `]},
							"then": {"effect": "audit"}
						}
					}
				}`
			}(),
		},
		{
			name: "built-in policy with BuiltIn type",
			json: `{
				"id": "/providers/Microsoft.Authorization/policyDefinitions/built-in-1",
				"name": "built-in-1",
				"properties": {
					"policyType": "BuiltIn",
					"displayName": "Allowed locations",
					"policyRule": {"if":{"not":{"field":"location","in":"[parameters('listOfAllowedLocations')]"}},"then":{"effect":"deny"}}
				}
			}`,
		},
		{
			name: "static policy type",
			json: `{
				"id": "/providers/Microsoft.Authorization/policyDefinitions/static-1",
				"name": "static-1",
				"properties": {
					"policyType": "Static",
					"displayName": "Static policy"
				}
			}`,
		},
		{
			name: "REPRODUCTION: assignPermissions as string instead of boolean (NSG_Flow_Log_v2_enable crash)",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/512ac622-4770-4df2-80c1-de76944c5744",
				"name": "512ac622-4770-4df2-80c1-de76944c5744",
				"properties": {
					"policyType": "Custom",
					"displayName": "NSG_Flow_Log_v2_enable",
					"parameters": {
						"storageId": {
							"type": "String",
							"metadata": {
								"displayName": "Storage Account ID",
								"description": "Storage Account for flow logs",
								"assignPermissions": "true"
							}
						},
						"nsgRegion": {
							"type": "String",
							"metadata": {
								"displayName": "NSG Region",
								"strongType": "location",
								"assignPermissions": true
							}
						}
					},
					"policyRule": {
						"if": {"field": "type", "equals": "Microsoft.Network/networkSecurityGroups"},
						"then": {"effect": "DeployIfNotExists", "details": {"type": "Microsoft.Network/networkWatchers/flowLogs"}}
					}
				}
			}`,
			expectErr: true, // SDK fails: "cannot unmarshal string into Go value of type bool"
		},
		{
			name: "assignPermissions as boolean (correct)",
			json: `{
				"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/good-policy",
				"name": "good-policy",
				"properties": {
					"policyType": "Custom",
					"parameters": {
						"param1": {
							"type": "String",
							"metadata": {
								"displayName": "Param 1",
								"assignPermissions": true
							}
						}
					},
					"policyRule": {"if": {"field": "type", "equals": "*"}, "then": {"effect": "audit"}}
				}
			}`,
			expectErr: false,
		},
		{
			name: "malformed JSON — truncated",
			json:      `{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyDefinitions/bad", "properties": {"policyType": "Cust`,
			expectErr: true,
		},
		{
			name:      "malformed JSON — wrong type for id",
			json:      `{"id": 12345, "name": "bad"}`,
			expectErr: true,
		},
		{
			name:      "empty JSON",
			json:      `{}`,
			expectErr: false,
		},
		{
			name:      "null JSON unmarshals to zero value",
			json:      `null`,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var def armpolicy.Definition
			err := json.Unmarshal([]byte(tt.json), &def)
			if tt.expectErr {
				assert.Error(t, err, "expected unmarshal to fail")
				return
			}
			require.NoError(t, err, "unmarshal should succeed")

			// If properties exist, verify marshal round-trip
			if def.Properties != nil {
				data, err := json.Marshal(def.Properties)
				require.NoError(t, err, "marshal of properties should succeed")
				assert.NotEmpty(t, data)
			}
		})
	}
}

// TestPolicyDefinitionListResult_UnmarshalPageResponse tests unmarshalling
// of the paginated list response, which is what NextPage() deserializes.
// This is the exact path that could crash in production.
func TestPolicyDefinitionListResult_UnmarshalPageResponse(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		expectErr bool
		count     int
	}{
		{
			name: "page with mixed built-in and custom",
			json: `{
				"value": [
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/builtin-1", "name": "builtin-1", "properties": {"policyType": "BuiltIn", "policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"audit"}}}},
					{"id": "/subscriptions/sub/providers/Microsoft.Authorization/policyDefinitions/custom-1", "name": "custom-1", "properties": {"policyType": "Custom", "policyRule": {"if":{"field":"type","equals":"*"},"then":{"effect":"deny"}}}},
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/builtin-2", "name": "builtin-2", "properties": {"policyType": "BuiltIn"}}
				]
			}`,
			count: 3,
		},
		{
			name: "page with unknown fields in definitions",
			json: `{
				"value": [
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/p1", "name": "p1", "systemData": {"createdBy": "user"}, "properties": {"policyType": "BuiltIn", "version": "1.0.0", "versions": ["1.0.0"]}},
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/p2", "name": "p2", "properties": {"policyType": "Custom", "version": "2.0.0"}}
				],
				"nextLink": "https://management.azure.com/subscriptions/sub/providers/Microsoft.Authorization/policyDefinitions?$skiptoken=abc"
			}`,
			count: 2,
		},
		{
			name:  "empty page",
			json:  `{"value": []}`,
			count: 0,
		},
		{
			name: "page with null value entries",
			json: `{
				"value": [
					null,
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/p1", "name": "p1", "properties": {"policyType": "BuiltIn"}},
					null
				]
			}`,
			count: 3,
		},
		{
			name: "page with definitions missing properties",
			json: `{
				"value": [
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/p1", "name": "p1"},
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/p2", "name": "p2", "properties": null}
				]
			}`,
			count: 2,
		},
		{
			name: "CRASH: page with assignPermissions string instead of bool (NSG_Flow_Log_v2_enable)",
			json: `{
				"value": [
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/good", "name": "good", "properties": {"policyType": "BuiltIn"}},
					{"id": "/subscriptions/sub/providers/Microsoft.Authorization/policyDefinitions/512ac622", "name": "512ac622", "properties": {
						"policyType": "Custom",
						"displayName": "NSG_Flow_Log_v2_enable",
						"parameters": {
							"storageId": {
								"type": "String",
								"metadata": {"displayName": "Storage Account ID", "assignPermissions": "true"}
							}
						},
						"policyRule": {"if": {"field": "type", "equals": "*"}, "then": {"effect": "audit"}}
					}},
					{"id": "/providers/Microsoft.Authorization/policyDefinitions/also-good", "name": "also-good", "properties": {"policyType": "BuiltIn"}}
				]
			}`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result armpolicy.DefinitionListResult
			err := json.Unmarshal([]byte(tt.json), &result)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "should unmarshal page response")
			assert.Len(t, result.Value, tt.count)

			// Re-marshal to verify round-trip stability
			data, err := json.Marshal(&result)
			require.NoError(t, err, "re-marshal should succeed")
			assert.NotEmpty(t, data)
		})
	}
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
	_ = out.Drain() // consume and discard

	// The error (if any) should NOT be "invalid Azure resource ID" or "too few segments"
	// It may be an ARM API error (nil cred), but not a parsing error.
	if gotErr != nil {
		assert.NotContains(t, gotErr.Error(), "invalid Azure resource ID",
			"should not fail with ID parsing error for subscription-scope IDs")
		assert.NotContains(t, gotErr.Error(), "too few segments",
			"should not fail with ID parsing error for subscription-scope IDs")
	}
}
