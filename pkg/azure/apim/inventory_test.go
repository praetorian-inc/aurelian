package apim

import "testing"

func TestClassifyAPI_UnauthenticatedWhenAllScopesEmpty(t *testing.T) {
	api := APIInventoryItem{
		APIID: "unauthed-api",
	}
	v := ClassifyAPI(api, AuthPosture{})
	if v.IsAuthenticated {
		t.Fatal("expected unauthenticated when every scope empty, got authenticated")
	}
	if v.SubscriptionRequired {
		t.Fatal("expected SubscriptionRequired=false")
	}
	if v.AuthScope != "" {
		t.Fatalf("expected empty AuthScope, got %q", v.AuthScope)
	}
}

func TestClassifyAPI_ServicePolicyAuthPropagates(t *testing.T) {
	api := APIInventoryItem{APIID: "a"}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when service policy has auth")
	}
	if v.AuthScope != "service" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "service")
	}
}

func TestClassifyAPI_APIPolicyAuth(t *testing.T) {
	api := APIInventoryItem{APIID: "a", APIPolicyAuth: AuthPosture{IPFilter: true}}
	v := ClassifyAPI(api, AuthPosture{})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when API policy has auth")
	}
	if v.AuthScope != "api" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "api")
	}
}

func TestClassifyAPI_ProductPolicyAuthRequiresSubscriptionRequired(t *testing.T) {
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: true,
		ProductPolicyAuths:   []AuthPosture{{}, {ValidateAzureADToken: true}},
	}
	v := ClassifyAPI(api, AuthPosture{})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when subscription-required is true and any product has auth")
	}
	if v.AuthScope != "product" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "product")
	}
}

func TestClassifyAPI_ProductPolicyWithoutSubscriptionRequiredDoesNotAuth(t *testing.T) {
	// Product policies only run for calls that present a subscription key. If
	// the API does not require a subscription, product policies are never
	// evaluated — so they do not satisfy authentication.
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: false,
		ProductPolicyAuths:   []AuthPosture{{ValidateJWT: true}},
	}
	v := ClassifyAPI(api, AuthPosture{})
	if v.IsAuthenticated {
		t.Fatal("product-policy auth must not satisfy API auth when subscription-required is false")
	}
}

func TestClassifyAPI_OperationPolicyDoesNotPromoteAPIToAuthed(t *testing.T) {
	api := APIInventoryItem{
		APIID: "a",
		Operations: []OperationInventoryItem{
			{OperationID: "op1", PolicyAuth: AuthPosture{ValidateJWT: true}},
			{OperationID: "op2", PolicyAuth: AuthPosture{}},
		},
	}
	v := ClassifyAPI(api, AuthPosture{})
	if v.IsAuthenticated {
		t.Fatal("API should be unauthenticated when only one operation has auth and higher scopes don't")
	}
}

func TestClassifyAPI_SubscriptionRequiredExposed(t *testing.T) {
	api := APIInventoryItem{APIID: "a", SubscriptionRequired: true}
	v := ClassifyAPI(api, AuthPosture{})
	if !v.SubscriptionRequired {
		t.Fatal("expected SubscriptionRequired=true to propagate")
	}
	if v.IsAuthenticated {
		t.Fatal("subscription-required alone does not satisfy authentication (subscription keys aren't an auth control)")
	}
}

func TestIsMCPServer(t *testing.T) {
	cases := []struct {
		name       string
		operations []OperationInventoryItem
		want       bool
	}{
		{
			name:       "no operations",
			operations: nil,
			want:       false,
		},
		{
			name: "streamable-HTTP MCP endpoint at /mcp",
			operations: []OperationInventoryItem{
				{URLTemplate: "/mcp"},
			},
			want: true,
		},
		{
			name: "SSE transport (/sse + /messages)",
			operations: []OperationInventoryItem{
				{URLTemplate: "/sse"},
				{URLTemplate: "/messages"},
			},
			want: true,
		},
		{
			name: "deprecated single /message endpoint",
			operations: []OperationInventoryItem{
				{URLTemplate: "/message"},
			},
			want: true,
		},
		{
			name: "case-insensitive match",
			operations: []OperationInventoryItem{
				{URLTemplate: "/MCP"},
			},
			want: true,
		},
		{
			name: "MCP path nested under a prefix",
			operations: []OperationInventoryItem{
				{URLTemplate: "/v1/mcp"},
			},
			want: true,
		},
		{
			name: "regular REST API operations do not match",
			operations: []OperationInventoryItem{
				{URLTemplate: "/users/{id}"},
				{URLTemplate: "/orders"},
			},
			want: false,
		},
		{
			name: "/mcp-like substrings in other words do not match",
			operations: []OperationInventoryItem{
				{URLTemplate: "/semcpanel"},
				{URLTemplate: "/messageboard"},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsMCPServer(tc.operations)
			if got != tc.want {
				t.Fatalf("IsMCPServer() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyAPI_ServiceScopePreferredOverAPIScope(t *testing.T) {
	api := APIInventoryItem{
		APIID:         "a",
		APIPolicyAuth: AuthPosture{ValidateJWT: true},
	}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if v.AuthScope != "service" {
		t.Fatalf("expected service scope to win when both authenticate, got %q", v.AuthScope)
	}
}
