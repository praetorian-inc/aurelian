package gcloudiam

import (
	"regexp"
	"strings"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

var (
	ksaRegex = regexp.MustCompile(`^serviceAccount:([^.]+)\.svc\.id\.goog\[([^/]+)/([^\]]+)\]$`)
)

type MemberNormalizer struct {
	memberCache map[string]*gcptypes.Resource
}

func NewMemberNormalizer() *MemberNormalizer {
	return &MemberNormalizer{
		memberCache: make(map[string]*gcptypes.Resource),
	}
}

func (mn *MemberNormalizer) NormalizeMember(member string) *gcptypes.Resource {
	if cached, ok := mn.memberCache[member]; ok {
		return cached
	}
	resource := mn.parseMember(member)
	mn.memberCache[member] = resource
	return resource
}

func (mn *MemberNormalizer) parseMember(member string) *gcptypes.Resource {
	properties := make(map[string]string)
	uri := member
	assetType := ""
	displayName := ""

	isDeleted := false
	originalMember := member
	if strings.HasPrefix(member, "deleted:") {
		isDeleted = true
		properties["deleted"] = "true"
		properties["originalEmail"] = member
		member = strings.TrimPrefix(member, "deleted:")
		uri = member
	}

	switch {
	case member == "allUsers":
		assetType = "iam.googleapis.com/AllUsers"
		uri = "allUsers"
		displayName = "allUsers"
	case member == "allAuthenticatedUsers":
		assetType = "iam.googleapis.com/AllAuthenticatedUsers"
		uri = "allAuthenticatedUsers"
		displayName = "allAuthenticatedUsers"
	case strings.HasPrefix(member, "user:"):
		assetType = "iam.googleapis.com/User"
		email := strings.TrimPrefix(member, "user:")
		properties["email"] = email
		uri = member
		displayName = email
	case strings.HasPrefix(member, "group:"):
		assetType = "iam.googleapis.com/Group"
		email := strings.TrimPrefix(member, "group:")
		properties["email"] = email
		uri = member
		displayName = email
	case strings.HasPrefix(member, "domain:"):
		assetType = "iam.googleapis.com/Domain"
		domain := strings.TrimPrefix(member, "domain:")
		properties["domain"] = domain
		uri = member
		displayName = domain
	case strings.HasPrefix(member, "serviceAccount:"):
		if matches := ksaRegex.FindStringSubmatch(member); matches != nil {
			assetType = "iam.googleapis.com/WorkloadIdentity"
			properties["ksaProjectId"] = matches[1]
			properties["kubernetesNamespace"] = matches[2]
			properties["kubernetesServiceAccount"] = matches[3]
			uri = member
			displayName = matches[2] + "/" + matches[3]
		} else {
			email := strings.TrimPrefix(member, "serviceAccount:")
			assetType = "iam.googleapis.com/ServiceAccount"
			properties["email"] = email
			if strings.Contains(email, ".gserviceaccount.com") && strings.HasPrefix(email, "service-") {
				properties["isGoogleManaged"] = "true"
				assetType = "iam.googleapis.com/ServiceAgent"
			}
			uri = member
			displayName = email
		}
	case strings.HasPrefix(member, "principal://"):
		uri = member
		if strings.Contains(member, "workforcePools") {
			assetType = "iam.googleapis.com/WorkforceIdentity"
			mn.parseWorkforcePrincipal(member, properties)
			if subject, ok := properties["workforceSubject"]; ok {
				displayName = subject
			} else {
				displayName = member
			}
		} else if strings.Contains(member, "workloadIdentityPools") {
			assetType = "iam.googleapis.com/WorkloadIdentity"
			mn.parseWorkloadPrincipal(member, properties)
			if subject, ok := properties["workloadSubject"]; ok {
				displayName = subject
			} else {
				displayName = member
			}
		}
		properties["principalUri"] = member
	case strings.HasPrefix(member, "principalSet://"):
		assetType = "iam.googleapis.com/PrincipalSet"
		properties["principalSetUri"] = member
		uri = member
		parts := strings.Split(member, "/")
		if len(parts) > 0 {
			displayName = parts[len(parts)-1]
		} else {
			displayName = member
		}
	case strings.HasPrefix(member, "projectOwner:"):
		assetType = "iam.googleapis.com/ProjectRole"
		projectID := strings.TrimPrefix(member, "projectOwner:")
		properties["projectId"] = projectID
		properties["roleType"] = "owner"
		uri = member
		displayName = "Project Owners: " + projectID
	case strings.HasPrefix(member, "projectEditor:"):
		assetType = "iam.googleapis.com/ProjectRole"
		projectID := strings.TrimPrefix(member, "projectEditor:")
		properties["projectId"] = projectID
		properties["roleType"] = "editor"
		uri = member
		displayName = "Project Editors: " + projectID
	case strings.HasPrefix(member, "projectViewer:"):
		assetType = "iam.googleapis.com/ProjectRole"
		projectID := strings.TrimPrefix(member, "projectViewer:")
		properties["projectId"] = projectID
		properties["roleType"] = "viewer"
		uri = member
		displayName = "Project Viewers: " + projectID
	}

	if isDeleted {
		if displayName == "" {
			displayName = member
		}
		displayName = "(deleted) " + displayName
		if originalMember != member {
			uri = originalMember
		}
	}

	if displayName == "" {
		displayName = uri
	}

	return &gcptypes.Resource{
		AssetType:  assetType,
		URI:        uri,
		Name:       displayName,
		Properties: properties,
	}
}

func (mn *MemberNormalizer) parseWorkforcePrincipal(uri string, properties map[string]string) {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if part == "workforcePools" && i+1 < len(parts) {
			poolName := strings.Join(parts[:i+2], "/")
			properties["workforcePoolName"] = strings.TrimPrefix(poolName, "principal://iam.googleapis.com/")
		}
		if part == "subject" && i+1 < len(parts) {
			properties["workforceSubject"] = strings.Join(parts[i:], "/")
		}
	}
}

func (mn *MemberNormalizer) parseWorkloadPrincipal(uri string, properties map[string]string) {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if part == "workloadIdentityPools" && i+1 < len(parts) {
			poolName := strings.Join(parts[:i+2], "/")
			properties["workloadPoolName"] = strings.TrimPrefix(poolName, "principal://iam.googleapis.com/")
		}
		if part == "subject" && i+1 < len(parts) {
			properties["workloadSubject"] = strings.Join(parts[i:], "/")
		}
	}
}

func (mn *MemberNormalizer) GetResourceKey(resource *gcptypes.Resource) string {
	return resource.URI
}
