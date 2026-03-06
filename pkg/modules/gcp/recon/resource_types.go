package recon

import (
	"fmt"
	"slices"
	"strings"
)

type resourceTypeInfo struct {
	aliases []string
}

var listResourceMap = map[string]resourceTypeInfo{
	"organizations":                                {aliases: []string{"organization", "org"}},
	"folders":                                      {aliases: []string{"folder"}},
	"projects":                                     {aliases: []string{"project"}},
	"compute.googleapis.com/Instance":              {aliases: []string{"vm", "instance"}},
	"compute.googleapis.com/ForwardingRule":        {aliases: []string{"forwardingrule"}},
	"compute.googleapis.com/GlobalForwardingRule":  {aliases: []string{"globalforwardingrule"}},
	"compute.googleapis.com/Address":               {aliases: []string{"address"}},
	"dns.googleapis.com/ManagedZone":               {aliases: []string{"dnszone", "managedzone"}},
	"storage.googleapis.com/Bucket":                {aliases: []string{"bucket"}},
	"sqladmin.googleapis.com/Instance":             {aliases: []string{"sql"}},
	"cloudfunctions.googleapis.com/Function":       {aliases: []string{"function", "cloudfunction"}},
	"run.googleapis.com/Service":                   {aliases: []string{"runservice", "cloudrunservice"}},
	"appengine.googleapis.com/Service":             {aliases: []string{"appengineservice"}},
	"artifactregistry.googleapis.com/Repository":   {aliases: []string{"artifactrepo"}},
	"artifactregistry.googleapis.com/DockerImage":  {aliases: []string{"dockerimage"}},
	"firebasehosting.googleapis.com/Site":          {aliases: []string{"firebase", "hostingsite"}},
}

var hierarchyTypes = []string{"organizations", "folders", "projects"}

// supportedInputTypes are the GCP resource types that modules accept as input scope.
var supportedInputTypes = []string{
	"cloudresourcemanager.googleapis.com/Organization",
	"cloudresourcemanager.googleapis.com/Folder",
	"cloudresourcemanager.googleapis.com/Project",
}

func resolveResourceTypes(requested []string) ([]string, error) {
	if len(requested) == 1 && strings.EqualFold(requested[0], "all") {
		return allResourceTypes(), nil
	}
	var resolved []string
	for _, req := range requested {
		canonical, err := resolveAlias(req)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(resolved, canonical) {
			resolved = append(resolved, canonical)
		}
	}
	return resolved, nil
}

func resolveAlias(alias string) (string, error) {
	lower := strings.ToLower(alias)
	for canonical, info := range listResourceMap {
		if strings.EqualFold(canonical, alias) || slices.Contains(info.aliases, lower) {
			return canonical, nil
		}
	}
	return "", fmt.Errorf("unsupported resource type %q", alias)
}

func filterResourceTypes(requested []string, supported []string) []string {
	if len(requested) == 1 && strings.EqualFold(requested[0], "all") {
		return supported
	}
	var filtered []string
	for _, r := range requested {
		canonical, err := resolveAlias(r)
		if err != nil {
			continue
		}
		if slices.Contains(supported, canonical) {
			filtered = append(filtered, canonical)
		}
	}
	return filtered
}

func allResourceTypes() []string {
	types := make([]string, 0, len(listResourceMap))
	for k := range listResourceMap {
		types = append(types, k)
	}
	slices.Sort(types)
	return types
}

func shouldFanOutToResources(requestedTypes []string) bool {
	for _, t := range requestedTypes {
		if !slices.Contains(hierarchyTypes, t) {
			return true
		}
	}
	return false
}
