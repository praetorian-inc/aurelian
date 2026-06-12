package enrichers

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	// OpenSearch and legacy Elasticsearch domains are both enumerated by the
	// native OpenSearchDomainEnumerator and reported under this single type.
	plugin.RegisterEnricher("AWS::OpenSearchService::Domain", enrichOpenSearchWrapper)
}

func enrichOpenSearchWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	return EnrichOpenSearchDomain(cfg, r)
}

// EnrichOpenSearchDomain flattens whether fine-grained access control is
// enabled (AdvancedSecurityOptions.Enabled, a nested map from CloudControl).
// When FGAC is disabled, the access policy is the only authorization layer.
func EnrichOpenSearchDomain(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	fgacEnabled := false
	if aso, ok := r.Properties["AdvancedSecurityOptions"].(map[string]any); ok {
		fgacEnabled, _ = aso["Enabled"].(bool)
	}
	r.Properties["FGACEnabled"] = fgacEnabled

	if policy, _ := r.Properties["AccessPolicies"].(string); policy != "" {
		r.Properties["HasWildcardAccessPolicy"] = accessPolicyHasWildcardPrincipal(policy)
	}
	return nil
}

// accessPolicyHasWildcardPrincipal reports whether an OpenSearch access policy
// document has an Allow statement granting a wildcard ("*") principal. It treats
// the Principal in its several JSON shapes: "*", {"AWS":"*"}, {"AWS":["*", ...]}.
func accessPolicyHasWildcardPrincipal(policy string) bool {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return false
	}

	var stmts []map[string]any
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var single map[string]any
		if err := json.Unmarshal(doc.Statement, &single); err != nil {
			return false
		}
		stmts = []map[string]any{single}
	}

	for _, s := range stmts {
		if effect, _ := s["Effect"].(string); effect != "Allow" {
			continue
		}
		if principalIsWildcard(s["Principal"]) {
			return true
		}
	}
	return false
}

func principalIsWildcard(principal any) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]any:
		for _, v := range p {
			if principalIsWildcard(v) {
				return true
			}
		}
	case []any:
		for _, v := range p {
			if principalIsWildcard(v) {
				return true
			}
		}
	}
	return false
}
