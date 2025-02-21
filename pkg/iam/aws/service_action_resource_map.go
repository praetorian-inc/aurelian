package aws

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// ServiceResourceMap defines valid actions for resource types within a service
type ServiceResourceMap struct {
	// Maps resource type to regex pattern for ARN matching
	ResourcePatterns map[string]*regexp.Regexp
	// Maps actions to valid resource types
	ActionResourceMap map[string][]string
}

// IsValidActionForResource checks if an action is valid for a given resource ARN
func IsValidActionForResource(action, resource string) bool {
	// Parse service and action name
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	service := parts[0]
	actionName := parts[1]

	// Get service map
	// assume true if we don't have a map for the service
	serviceMap, exists := serviceResourceMaps[service]
	if !exists {
		return true
	}

	// Get valid resource types for action
	validResourceTypes, exists := serviceMap.ActionResourceMap[actionName]
	if !exists {
		return false
	}

	// Check each valid resource type
	for _, resourceType := range validResourceTypes {
		// Get pattern for resource type
		pattern, exists := serviceMap.ResourcePatterns[resourceType]
		if !exists {
			continue
		}

		// Check if resource ARN matches pattern
		if pattern.MatchString(resource) {
			return true
		}
	}

	return false
}

func GetResourcePatternsFromAction(action Action) []*regexp.Regexp {
	patterns := []*regexp.Regexp{}
	service := action.Service()
	act := strings.Split(string(action), ":")[1]

	serviceMap, exists := serviceResourceMaps[service]
	if exists {
		for _, resourceType := range serviceMap.ActionResourceMap[act] {
			if serviceMap.ResourcePatterns[resourceType] != nil {
				patterns = append(patterns, serviceMap.ResourcePatterns[resourceType])
			}
		}
		slog.Debug("Resource patterns", slog.String("action", string(action)), slog.String("patterns", fmt.Sprintf("%v", patterns)))
		return patterns

	}

	return []*regexp.Regexp{regexp.MustCompile(fmt.Sprintf("arn:aws:%s:*:*:*", service))}

}

// serviceResourceMaps contains the mappings for each AWS service
var serviceResourceMaps = map[string]ServiceResourceMap{
	"iam": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"user":               regexp.MustCompile(`^arn:aws:iam::\d{12}:user/.*`),
			"group":              regexp.MustCompile(`^arn:aws:iam::\d{12}:group/.*`),
			"role":               regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.*`),
			"policy":             regexp.MustCompile(`^arn:aws:iam::(\d{12}|aws):policy/.*`),
			"instance-profile":   regexp.MustCompile(`^arn:aws:iam::\d{12}:instance-profile/.*`),
			"mfa":                regexp.MustCompile(`^arn:aws:iam::\d{12}:mfa/.*`),
			"oidc-provider":      regexp.MustCompile(`^arn:aws:iam::\d{12}:oidc-provider/.*`),
			"saml-provider":      regexp.MustCompile(`^arn:aws:iam::\d{12}:saml-provider/.*`),
			"server-certificate": regexp.MustCompile(`^arn:aws:iam::\d{12}:server-certificate/.*`),
		},
		ActionResourceMap: map[string][]string{
			"AddClientIDToOpenIDConnectProvider":      {"oidc-provider"},
			"AddRoleToInstanceProfile":                {"instance-profile"},
			"AddUserToGroup":                          {"group"},
			"AttachGroupPolicy":                       {"group"},
			"AttachRolePolicy":                        {"role"},
			"AttachUserPolicy":                        {"user"},
			"ChangePassword":                          {"user"},
			"CreateAccessKey":                         {"user"},
			"CreateGroup":                             {"group"},
			"CreateInstanceProfile":                   {"instance-profile"},
			"CreateLoginProfile":                      {"user"},
			"CreateOpenIDConnectProvider":             {"oidc-provider"},
			"CreatePolicy":                            {"policy"},
			"CreatePolicyVersion":                     {"policy"},
			"CreateRole":                              {"role"},
			"CreateSAMLProvider":                      {"saml-provider"},
			"CreateServiceLinkedRole":                 {"role"},
			"CreateServiceSpecificCredential":         {"user"},
			"CreateUser":                              {"user"},
			"CreateVirtualMFADevice":                  {"mfa"},
			"DeactivateMFADevice":                     {"user"},
			"DeleteAccessKey":                         {"user"},
			"DeleteGroup":                             {"group"},
			"DeleteGroupPolicy":                       {"group"},
			"DeleteInstanceProfile":                   {"instance-profile"},
			"DeleteLoginProfile":                      {"user"},
			"DeleteOpenIDConnectProvider":             {"oidc-provider"},
			"DeletePolicy":                            {"policy"},
			"DeletePolicyVersion":                     {"policy"},
			"DeleteRole":                              {"role"},
			"DeleteRolePermissionsBoundary":           {"role"},
			"DeleteRolePolicy":                        {"role"},
			"DeleteSAMLProvider":                      {"saml-provider"},
			"DeleteSSHPublicKey":                      {"user"},
			"DeleteServerCertificate":                 {"server-certificate"},
			"DeleteServiceLinkedRole":                 {"role"},
			"DeleteServiceSpecificCredential":         {"user"},
			"DeleteSigningCertificate":                {"user"},
			"DeleteUser":                              {"user"},
			"DeleteUserPermissionsBoundary":           {"user"},
			"DeleteUserPolicy":                        {"user"},
			"DeleteVirtualMFADevice":                  {"mfa"},
			"DetachGroupPolicy":                       {"group"},
			"DetachRolePolicy":                        {"role"},
			"DetachUserPolicy":                        {"user"},
			"EnableMFADevice":                         {"user"},
			"GenerateServiceLastAccessedDetails":      {"group", "role", "user", "policy"},
			"GetAccessKeyLastUsed":                    {"user"},
			"GetGroup":                                {"group"},
			"GetGroupPolicy":                          {"group"},
			"GetInstanceProfile":                      {"instance-profile"},
			"GetLoginProfile":                         {"user"},
			"GetMFADevice":                            {"user"},
			"GetOpenIDConnectProvider":                {"oidc-provider"},
			"GetPolicy":                               {"policy"},
			"GetPolicyVersion":                        {"policy"},
			"GetRole":                                 {"role"},
			"GetRolePolicy":                           {"role"},
			"GetSAMLProvider":                         {"saml-provider"},
			"GetSSHPublicKey":                         {"user"},
			"GetServerCertificate":                    {"server-certificate"},
			"GetServiceLinkedRoleDeletionStatus":      {"role"},
			"GetUser":                                 {"user"},
			"GetUserPolicy":                           {"user"},
			"ListAccessKeys":                          {"user"},
			"ListAttachedGroupPolicies":               {"group"},
			"ListAttachedRolePolicies":                {"role"},
			"ListAttachedUserPolicies":                {"user"},
			"ListGroupPolicies":                       {"group"},
			"ListGroupsForUser":                       {"user"},
			"ListInstanceProfileTags":                 {"instance-profile"},
			"ListInstanceProfilesForRole":             {"role"},
			"ListMFADeviceTags":                       {"mfa"},
			"ListMFADevices":                          {"user"},
			"ListOpenIDConnectProviderTags":           {"oidc-provider"},
			"ListPolicyTags":                          {"policy"},
			"ListPolicyVersions":                      {"policy"},
			"ListRolePolicies":                        {"role"},
			"ListRoleTags":                            {"role"},
			"ListSAMLProviderTags":                    {"saml-provider"},
			"ListSSHPublicKeys":                       {"user"},
			"ListServerCertificateTags":               {"server-certificate"},
			"ListServiceSpecificCredentials":          {"user"},
			"ListSigningCertificates":                 {"user"},
			"ListUserPolicies":                        {"user"},
			"ListUserTags":                            {"user"},
			"PassRole":                                {"role"},
			"PutGroupPolicy":                          {"group"},
			"PutRolePermissionsBoundary":              {"role"},
			"PutRolePolicy":                           {"role"},
			"PutUserPermissionsBoundary":              {"user"},
			"PutUserPolicy":                           {"user"},
			"RemoveClientIDFromOpenIDConnectProvider": {"oidc-provider"},
			"RemoveRoleFromInstanceProfile":           {"instance-profile"},
			"RemoveUserFromGroup":                     {"group"},
			"ResetServiceSpecificCredential":          {"user"},
			"ResyncMFADevice":                         {"user"},
			"SetDefaultPolicyVersion":                 {"policy"},
			"TagInstanceProfile":                      {"instance-profile"},
			"TagMFADevice":                            {"mfa"},
			"TagOpenIDConnectProvider":                {"oidc-provider"},
			"TagPolicy":                               {"policy"},
			"TagRole":                                 {"role"},
			"TagSAMLProvider":                         {"saml-provider"},
			"TagServerCertificate":                    {"server-certificate"},
			"TagUser":                                 {"user"},
			"UntagInstanceProfile":                    {"instance-profile"},
			"UntagMFADevice":                          {"mfa"},
			"UntagOpenIDConnectProvider":              {"oidc-provider"},
			"UntagPolicy":                             {"policy"},
			"UntagRole":                               {"role"},
			"UntagSAMLProvider":                       {"saml-provider"},
			"UntagServerCertificate":                  {"server-certificate"},
			"UntagUser":                               {"user"},
			"UpdateAccessKey":                         {"user"},
			"UpdateAssumeRolePolicy":                  {"role"},
			"UpdateGroup":                             {"group"},
			"UpdateLoginProfile":                      {"user"},
			"UpdateOpenIDConnectProviderThumbprint":   {"oidc-provider"},
			"UpdateRole":                              {"role"},
			"UpdateRoleDescription":                   {"role"},
			"UpdateSAMLProvider":                      {"saml-provider"},
			"UpdateSSHPublicKey":                      {"user"},
			"UpdateServerCertificate":                 {"server-certificate"},
			"UpdateServiceSpecificCredential":         {"user"},
			"UpdateSigningCertificate":                {"user"},
			"UpdateUser":                              {"user"},
			"UploadSSHPublicKey":                      {"user"},
			"UploadServerCertificate":                 {"server-certificate"},
			"UploadSigningCertificate":                {"user"},
		},
	},
	"ec2": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"instance": regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:instance/.*`),
			"volume":   regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:volume/.*`),
			"snapshot": regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:snapshot/.*`),
			"image":    regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:image/.*`),
		},
		ActionResourceMap: map[string][]string{
			"RunInstances": {"instance"},
		},
	},
	"cloudformation": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"stack":    regexp.MustCompile(`^arn:aws:cloudformation:[a-z-0-9]+:\d{12}:stack/.*`),
			"stackset": regexp.MustCompile(`^arn:aws:cloudformation:[a-z-0-9]+:\d{12}:stackset/.*`),
		},
		ActionResourceMap: map[string][]string{
			"CreateStack":      {"stack"},
			"UpdateStack":      {"stack"},
			"SetStackPolicy":   {"stack"},
			"CreateChangeSet":  {"stack"},
			"ExecuteChangeSet": {"stack"},
			"CreateStackSet":   {"stackset"},
			"UpdateStackSet":   {"stackset"},
		},
	},
}
