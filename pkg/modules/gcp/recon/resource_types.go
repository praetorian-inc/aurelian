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
	for canonical := range listResourceMap {
		if strings.EqualFold(canonical, alias) {
			return canonical, nil
		}
	}
	for canonical, info := range listResourceMap {
		if slices.Contains(info.aliases, lower) {
			return canonical, nil
		}
	}
	return "", fmt.Errorf("unsupported resource type %q", alias)
}

func validateResourceTypes(types []string) error {
	if len(types) == 1 && strings.EqualFold(types[0], "all") {
		return nil
	}
	for _, t := range types {
		if _, err := resolveAlias(t); err != nil {
			return err
		}
	}
	return nil
}

func allResourceTypes() []string {
	types := make([]string, 0, len(listResourceMap))
	for k := range listResourceMap {
		types = append(types, k)
	}
	slices.Sort(types)
	return types
}

func nonHierarchyTypes() []string {
	var types []string
	for k := range listResourceMap {
		if !slices.Contains(hierarchyTypes, k) {
			types = append(types, k)
		}
	}
	slices.Sort(types)
	return types
}

func shouldFanOutToResources(requestedTypes []string) bool {
	if len(requestedTypes) == 1 && strings.EqualFold(requestedTypes[0], "all") {
		return true
	}
	for _, t := range requestedTypes {
		canonical, err := resolveAlias(t)
		if err != nil {
			continue
		}
		if !slices.Contains(hierarchyTypes, canonical) {
			return true
		}
	}
	return false
}
