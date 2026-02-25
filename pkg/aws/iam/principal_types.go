package iam

type PrincipalType string

// AWS principal types
const (
	PrincipalTypeAWS            PrincipalType = "AWS"
	PrincipalTypeService        PrincipalType = "Service"
	PrincipalTypeFederated      PrincipalType = "Federated"
	PrincipalTypeCanonicalUser  PrincipalType = "CanonicalUser"
	PrincipalTypeUser           PrincipalType = "User"
	PrincipalTypeRole           PrincipalType = "Role"
	PrincipalTypeRoleSession    PrincipalType = "RoleSession"
	PrincipalTypeFederatedUser  PrincipalType = "FederatedUser"
	PrincipalTypeServiceAccount PrincipalType = "ServiceAccount"
	PrincipalTypeRoot           PrincipalType = "Root"
	PrincipalTypeUnknown        PrincipalType = "Unknown"
)
