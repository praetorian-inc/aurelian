package apim

// APIInventoryItem captures everything we need to know about a single API
// within one APIM service in order to classify its authentication posture.
type APIInventoryItem struct {
	APIID                string
	DisplayName          string
	Path                 string
	Protocols            []string
	SubscriptionRequired bool
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
