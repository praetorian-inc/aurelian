package apim

import "strings"

// APIInventoryItem captures everything we need to know about a single API
// within one APIM service in order to classify its authentication posture.
type APIInventoryItem struct {
	APIID                string
	DisplayName          string
	Path                 string
	Protocols            []string
	SubscriptionRequired bool
	IsMCPServer          bool
	APIPolicyAuth        AuthPosture
	ProductPolicyAuths   []AuthPosture
	Operations           []OperationInventoryItem
}

// OperationInventoryItem captures one operation within an API.
type OperationInventoryItem struct {
	OperationID string
	DisplayName string
	Method      string
	URLTemplate string
	PolicyAuth  AuthPosture
}

// APIVerdict is the classification of an API's authentication posture, rolled
// up from the service-/product-/api-scope policies. Operation-scope auth is
// not rolled up here: a single authenticated operation does not mean the API
// as a whole requires authentication.
type APIVerdict struct {
	IsAuthenticated      bool
	SubscriptionRequired bool
	AuthScope            string // "service" | "api" | "product" | ""
}

// mcpOperationSuffixes is the set of URL-template trailing segments that
// identify an API as a Model Context Protocol server. MCP's Streamable-HTTP
// transport uses /mcp, and the (deprecated) SSE transport uses /sse plus
// either /messages (current) or /message (early drafts).
var mcpOperationSuffixes = []string{"/mcp", "/sse", "/messages", "/message"}

// IsMCPServer reports whether any operation's URL template identifies the API
// as an MCP server. Checks are case-insensitive, ignore trailing slashes, and
// match either the full template or a trailing path segment, so "/mcp",
// "/mcp/", and "/v1/mcp" all count.
func IsMCPServer(operations []OperationInventoryItem) bool {
	for _, op := range operations {
		tmpl := strings.TrimRight(strings.ToLower(op.URLTemplate), "/")
		for _, suffix := range mcpOperationSuffixes {
			if tmpl == suffix || strings.HasSuffix(tmpl, suffix) {
				return true
			}
		}
	}
	return false
}

// ClassifyAPI returns an APIVerdict summarizing the given API's auth posture.
//
// The classifier respects APIM's policy inheritance chain (Global → Product →
// API → Operation). A child scope inherits parent auth only when the child's
// inbound section calls `<base />` (tracked as AuthPosture.HasBase). When a
// scope has no custom policy at all, callers are expected to pass a posture
// with HasBase=true (use InheritedFromParent), matching APIM's behavior of
// implicitly running the parent.
//
// Authentication rules, conservative side:
//
//   - API-scope auth (api.APIPolicyAuth.HasAuth) always counts — it runs
//     regardless of <base /> and regardless of subscription state.
//   - Service-scope auth counts only when api.APIPolicyAuth.HasBase is true.
//     Otherwise the API's policy short-circuits the chain and service-scope
//     `<validate-jwt>` etc. never executes.
//   - Product-scope auth counts only when (a) api.SubscriptionRequired is
//     true (calls go through a product), (b) api.APIPolicyAuth.HasBase is
//     true (so product policy runs), (c) at least one product is associated,
//     and (d) EVERY associated product enforces auth — either via its own
//     policy or by chaining to a service-scope auth via <base />. If any
//     product is open, an attacker subscribes to the weakest one and bypasses
//     the others.
//
// Precedence on label: when multiple scopes authenticate, the chain is
// reported in order service > api > product so the operator sees the
// outermost gate.
func ClassifyAPI(api APIInventoryItem, servicePolicyAuth AuthPosture) APIVerdict {
	v := APIVerdict{SubscriptionRequired: api.SubscriptionRequired}

	serviceApplies := servicePolicyAuth.HasAuth() && api.APIPolicyAuth.HasBase
	apiApplies := api.APIPolicyAuth.HasAuth()

	switch {
	case serviceApplies:
		v.IsAuthenticated = true
		v.AuthScope = "service"
	case apiApplies:
		v.IsAuthenticated = true
		v.AuthScope = "api"
	case api.SubscriptionRequired && api.APIPolicyAuth.HasBase && len(api.ProductPolicyAuths) > 0:
		allProductsAuth := true
		for _, p := range api.ProductPolicyAuths {
			// A product authenticates if it has its own auth, OR it inherits
			// service auth via <base /> (which only fires when service has auth).
			productAuthed := p.HasAuth() || (p.HasBase && servicePolicyAuth.HasAuth())
			if !productAuthed {
				allProductsAuth = false
				break
			}
		}
		if allProductsAuth {
			v.IsAuthenticated = true
			v.AuthScope = "product"
		}
	}
	return v
}
