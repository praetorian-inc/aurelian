package enrichers

import (
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

type iamBinding struct {
	Role    string
	Members []string
}

var anonymousMembers = []string{"allUsers", "allAuthenticatedUsers"}

// enrichIAMBindings sets IAMBindings on the resource and detects anonymous access.
func enrichIAMBindings(r *output.GCPResource, bindings []iamBinding) {
	if r.Properties == nil {
		r.Properties = make(map[string]any)
	}
	r.Properties["IAMBindings"] = bindings

	for _, b := range bindings {
		for _, member := range b.Members {
			if slices.Contains(anonymousMembers, member) {
				r.Properties["AnonymousAccess"] = true
				r.Properties["AnonymousAccessInfo"] = map[string]any{
					"role":   b.Role,
					"member": member,
				}
				return
			}
		}
	}
}
