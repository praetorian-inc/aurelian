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
	// API has no own policy → APIPolicyAuth represents "inherits from parent".
	api := APIInventoryItem{APIID: "a", APIPolicyAuth: InheritedFromParent()}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when service policy has auth and API inherits via <base />")
	}
	if v.AuthScope != "service" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "service")
	}
}

func TestClassifyAPI_ServicePolicyBypassedWhenAPILacksBase(t *testing.T) {
	// API has its own custom inbound policy, but that policy doesn't include
	// <base />. Service-scope <validate-jwt> never executes — even though the
	// service has auth configured, the API is effectively unauthenticated.
	api := APIInventoryItem{
		APIID:         "a",
		APIPolicyAuth: AuthPosture{}, // custom policy, no auth elements, no <base />
	}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if v.IsAuthenticated {
		t.Fatal("service-scope auth must NOT propagate when API policy lacks <base />")
	}
	if v.AuthScope != "" {
		t.Fatalf("AuthScope = %q, want empty (no scope authenticates)", v.AuthScope)
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

func TestClassifyAPI_ProductPolicyAuthRequiresAllProductsAuthenticated(t *testing.T) {
	// API is in two products; both enforce JWT. With SubscriptionRequired AND
	// APIPolicyAuth.HasBase the product chain runs. Because every product
	// authenticates, the API is authenticated.
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: true,
		APIPolicyAuth:        InheritedFromParent(),
		ProductPolicyAuths: []AuthPosture{
			{ValidateJWT: true},
			{ValidateAzureADToken: true},
		},
	}
	v := ClassifyAPI(api, AuthPosture{})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when every product enforces auth")
	}
	if v.AuthScope != "product" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "product")
	}
}

func TestClassifyAPI_ProductPolicyAuthRejectsAnyOpenProduct(t *testing.T) {
	// One product has no auth and no <base />. An attacker subscribes to
	// that product to bypass the auth on the other product — so the API is
	// effectively unauthenticated even though product B enforces JWT.
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: true,
		APIPolicyAuth:        InheritedFromParent(),
		ProductPolicyAuths: []AuthPosture{
			{},                         // weak product: no own auth, no inheritance
			{ValidateJWT: true},        // strong product
		},
	}
	v := ClassifyAPI(api, AuthPosture{})
	if v.IsAuthenticated {
		t.Fatal("API must not be classified authenticated when any associated product is open")
	}
}

func TestClassifyAPI_ProductInheritsServiceAuthViaBase(t *testing.T) {
	// Product B has no own auth but does include <base /> — so it inherits
	// service-scope JWT. Product A has its own JWT. All products authenticate.
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: true,
		APIPolicyAuth:        InheritedFromParent(),
		ProductPolicyAuths: []AuthPosture{
			{ValidateJWT: true},
			{HasBase: true}, // inherits service
		},
	}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if !v.IsAuthenticated {
		t.Fatal("expected authenticated when products either own auth or inherit via base")
	}
	// AuthScope should be 'service' in this case because service auth applies
	// directly to the API too (api.HasBase + service.HasAuth).
	if v.AuthScope != "service" {
		t.Fatalf("AuthScope = %q, want %q", v.AuthScope, "service")
	}
}

func TestClassifyAPI_ProductBaseWithoutServiceAuthDoesNotInherit(t *testing.T) {
	// Product B has <base /> but service has no auth. Product B does not
	// effectively authenticate. Product A has own auth. The weak product
	// breaks the chain.
	api := APIInventoryItem{
		APIID:                "a",
		SubscriptionRequired: true,
		APIPolicyAuth:        InheritedFromParent(),
		ProductPolicyAuths: []AuthPosture{
			{ValidateJWT: true},
			{HasBase: true}, // inherits ... but service has nothing to inherit
		},
	}
	v := ClassifyAPI(api, AuthPosture{}) // service has no auth
	if v.IsAuthenticated {
		t.Fatal("product with <base /> must not authenticate when service has no auth")
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
			name: "trailing slash is ignored",
			operations: []OperationInventoryItem{
				{URLTemplate: "/mcp/"},
			},
			want: true,
		},
		{
			name: "trailing slash on nested MCP path",
			operations: []OperationInventoryItem{
				{URLTemplate: "/v1/mcp/"},
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
	// Both service and API authenticate, AND the API includes <base /> so
	// service auth actually runs. Service is reported as the outermost gate.
	api := APIInventoryItem{
		APIID:         "a",
		APIPolicyAuth: AuthPosture{ValidateJWT: true, HasBase: true},
	}
	v := ClassifyAPI(api, AuthPosture{ValidateJWT: true})
	if v.AuthScope != "service" {
		t.Fatalf("expected service scope to win when both authenticate and API has <base />, got %q", v.AuthScope)
	}
}
