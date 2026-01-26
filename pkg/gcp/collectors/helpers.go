package gcloudcollectors

import (
	"fmt"
	"regexp"
	"strings"
)

func normalizeOrgName(orgID string) string {
	if strings.HasPrefix(orgID, "organizations/") {
		return orgID
	}
	return "organizations/" + orgID
}

func normalizeFolderName(folderID string) string {
	if strings.HasPrefix(folderID, "folders/") {
		return folderID
	}
	return "folders/" + folderID
}

func normalizeProjectName(projectID string) string {
	if strings.HasPrefix(projectID, "projects/") {
		return projectID
	}
	return "projects/" + projectID
}

func extractIDFromName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return name
}

func convertURIToDenyPolicyParent(uri string) string {
	encodedURI := strings.ReplaceAll(uri, "/", "%2F") // needed
	return "policies/cloudresourcemanager.googleapis.com%2F" + encodedURI + "/denypolicies"
}

func isSysProject(projectID, displayName string) bool {
	sysPatterns := []string{
		"sys-",
		"script-editor-",
		"apps-script-",
		"system-",
		"firebase-",
		"cloud-build-",
		"gcf-",
		"gae-",
	}
	projectIDLower := strings.ToLower(projectID)
	displayNameLower := strings.ToLower(displayName)
	for _, pattern := range sysPatterns {
		if strings.HasPrefix(projectIDLower, pattern) || strings.HasPrefix(displayNameLower, pattern) {
			return true
		}
	}
	return false
}

func extractIDFromURI(uri string) string {
	parts := []rune(uri)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '/' {
			return string(parts[i+1:])
		}
	}
	return uri
}

func toFullURI(shortName string) string {
	if strings.HasPrefix(shortName, "//") {
		return shortName
	}
	return "//cloudresourcemanager.googleapis.com/" + shortName
}

func toShortName(fullURI string) string {
	if strings.HasPrefix(fullURI, "//cloudresourcemanager.googleapis.com/") {
		return strings.TrimPrefix(fullURI, "//cloudresourcemanager.googleapis.com/")
	}
	return fullURI
}

func ExtractProjectIDFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	domainParts := strings.Split(parts[1], ".")
	if len(domainParts) > 0 {
		return domainParts[0]
	}
	return ""
}

func ExtractProjectNumber(uri string) string {
	re := regexp.MustCompile(`projects/(\d+)`)
	matches := re.FindStringSubmatch(uri)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func ExtractProjectIDFromURI(uri string) string {
	re := regexp.MustCompile(`projects/([^/]+)`)
	matches := re.FindStringSubmatch(uri)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func BuildFullResourceURI(service string, shortName string, projectIDToNumber map[string]string) string {
	projectID := ExtractProjectIDFromURI(shortName)
	if projectID == "" {
		return "//" + service + "/" + shortName
	}

	projectNumber, ok := projectIDToNumber[projectID]
	if !ok {
		return "//" + service + "/" + shortName
	}

	updatedName := strings.Replace(shortName, "projects/"+projectID, "projects/"+projectNumber, 1)
	return "//" + service + "/" + updatedName
}

func BuildServiceAccountURI(email string, projectNumber string) string {
	return fmt.Sprintf("//iam.googleapis.com/projects/%s/serviceAccounts/%s", projectNumber, email)
}

func BuildProjectParentURI(projectNumber string) string {
	return fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", projectNumber)
}

func NormalizeToFullURI(uri string) string {
	if strings.HasPrefix(uri, "//") {
		return uri
	}
	return "//cloudresourcemanager.googleapis.com/" + uri
}
