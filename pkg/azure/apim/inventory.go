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
// as an MCP server. Checks are case-insensitive and match either the full
// template or a trailing path segment, so both "/mcp" and "/v1/mcp" count.
func IsMCPServer(operations []OperationInventoryItem) bool {
	for _, op := range operations {
		tmpl := strings.ToLower(op.URLTemplate)
		for _, suffix := range mcpOperationSuffixes {
			if tmpl == suffix || strings.HasSuffix(tmpl, suffix) {
				return true
			}
		}
	}
	return false
}

// ClassifyAPI returns an APIVerdict summarizing the given API's auth posture.
// Precedence when multiple scopes authenticate: service > api > product.
func ClassifyAPI(api APIInventoryItem, servicePolicyAuth AuthPosture) APIVerdict {
	v := APIVerdict{SubscriptionRequired: api.SubscriptionRequired}
	switch {
	case servicePolicyAuth.HasAuth():
		v.IsAuthenticated = true
		v.AuthScope = "service"
	case api.APIPolicyAuth.HasAuth():
		v.IsAuthenticated = true
		v.AuthScope = "api"
	case api.SubscriptionRequired:
		for _, p := range api.ProductPolicyAuths {
			if p.HasAuth() {
				v.IsAuthenticated = true
				v.AuthScope = "product"
				break
			}
		}
	}
	return v
}
