package common

import (
	"fmt"
	"log/slog"
	"slices"

	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

// shows implemented resource types only for list resources links
var listResourceMap = map[tab.CloudResourceType][]string{
	// Storage
	tab.GCPResourceBucket:      {"bucket"},
	tab.GCPResourceSQLInstance: {"sql"},

	// Compute
	tab.GCPResourceInstance: {"vm", "instance"},

	// Networking
	tab.GCPResourceForwardingRule:       {"forwardingrule"},
	tab.GCPResourceGlobalForwardingRule: {"globalforwardingrule", "globalforwarding"},
	tab.GCPResourceDNSManagedZone:       {"dnszone", "managedzone"},
	tab.GCPResourceAddress:              {"address"},

	// Applications
	tab.GCPResourceFunction:         {"function", "functionv2"},
	tab.GCPResourceFunctionV1:       {"functionv1", "cloudfunction"},
	tab.GCPResourceCloudRunService:  {"runservice", "cloudrunservice"},
	tab.GCPResourceAppEngineService: {"appengineservice", "appengine"},

	// Containers
	tab.GCRArtifactRepository:     {"artifactrepo"},
	tab.GCRContainerImage:         {"containerimage"},
	tab.GCRArtifactoryDockerImage: {"dockerimage", "artifactoryimage"},

	// Hierarchy (Info only - use hierarchy modules for listing)
	tab.GCPResourceProject:      {"project"},
	tab.GCPResourceFolder:       {"folder"},
	tab.GCPResourceOrganization: {"organization", "org"},
}

// shows implemented resources only for secrets scanning links
var secretsResourceMap = map[tab.CloudResourceType][]string{
	// Storage - scans bucket objects
	tab.GCPResourceBucket: {"bucket"},

	// Compute - scans instance metadata and user data
	tab.GCPResourceInstance: {"vm", "instance"},

	// Applications - scans source code and environment variables
	tab.GCPResourceFunction:         {"function", "functionv2"},
	tab.GCPResourceFunctionV1:       {"functionv1", "cloudfunction"},
	tab.GCPResourceCloudRunService:  {"runservice", "cloudrunservice"},
	tab.GCPResourceAppEngineService: {"appengineservice", "appengine"},

	// Containers - scans container image layers
	tab.GCRContainerImage:         {"containerimage"},
	tab.GCRArtifactoryDockerImage: {"dockerimage", "artifactoryimage"},
}

func GetListResourceMap() map[tab.CloudResourceType][]string {
	return listResourceMap
}

func GetSecretsResourceMap() map[tab.CloudResourceType][]string {
	return secretsResourceMap
}

func ResrouceIdentifier(s string) tab.CloudResourceType {
	return resourceIdentifierFromMap(s, listResourceMap)
}

func SecretsResourceIdentifier(s string) tab.CloudResourceType {
	return resourceIdentifierFromMap(s, secretsResourceMap)
}

func resourceIdentifierFromMap(s string, resourceMap map[tab.CloudResourceType][]string) tab.CloudResourceType {
	for k, v := range resourceMap {
		if slices.Contains(v, s) {
			return k
		} else if s == k.String() {
			return k
		}
	}
	slog.Error("Unsupported or unknown resource type", "resource", s)
	return tab.ResourceTypeUnknown
}

func ValidateResourceTypes(resourceTypes []string, validatorFunc func(string) tab.CloudResourceType) error {
	if len(resourceTypes) > 0 && resourceTypes[0] != "all" {
		for _, rt := range resourceTypes {
			if validatorFunc(rt) == tab.ResourceTypeUnknown {
				return fmt.Errorf("unsupported resource type: %s", rt)
			}
		}
	}
	return nil
}
