package types

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/store"
)

// ---------------------------------------------------------------------------
// Entra ID entity types
// ---------------------------------------------------------------------------

// EntraUser represents an Entra ID (Azure AD) user.
type EntraUser struct {
	ObjectID          string         `json:"id"`
	DisplayName       string         `json:"displayName"`
	UserPrincipalName string         `json:"userPrincipalName"`
	Mail              string         `json:"mail,omitempty"`
	AccountEnabled    bool           `json:"accountEnabled"`
	UserType          string         `json:"userType,omitempty"`
	CreatedDateTime   string         `json:"createdDateTime,omitempty"`
	Credentials       []CredentialInfo `json:"credentials,omitempty"`
}

// EntraGroup represents an Entra ID group.
type EntraGroup struct {
	ObjectID        string `json:"id"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description,omitempty"`
	SecurityEnabled bool   `json:"securityEnabled"`
	MailEnabled     bool   `json:"mailEnabled,omitempty"`
	GroupTypes      []string `json:"groupTypes,omitempty"`
}

// EntraServicePrincipal represents an Entra ID service principal.
type EntraServicePrincipal struct {
	ObjectID             string   `json:"id"`
	DisplayName          string   `json:"displayName"`
	AppID                string   `json:"appId"`
	ServicePrincipalType string   `json:"servicePrincipalType"`
	AccountEnabled       bool     `json:"accountEnabled,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
}

// EntraApplication represents an Entra ID application registration.
type EntraApplication struct {
	ObjectID    string         `json:"id"`
	DisplayName string         `json:"displayName"`
	AppID       string         `json:"appId"`
	SignInAudience string     `json:"signInAudience,omitempty"`
	Credentials []CredentialInfo `json:"credentials,omitempty"`
}

// CredentialInfo represents a credential (password or certificate) on a principal.
type CredentialInfo struct {
	KeyID          string `json:"keyId"`
	DisplayName    string `json:"displayName,omitempty"`
	Type           string `json:"type"`
	StartDateTime  string `json:"startDateTime,omitempty"`
	EndDateTime    string `json:"endDateTime,omitempty"`
}

// EntraDevice represents an Entra ID device.
type EntraDevice struct {
	ObjectID        string `json:"id"`
	DisplayName     string `json:"displayName"`
	OperatingSystem string `json:"operatingSystem,omitempty"`
	TrustType       string `json:"trustType,omitempty"`
	AccountEnabled  bool   `json:"accountEnabled,omitempty"`
}

// DirectoryRole represents an activated Entra ID directory role.
type DirectoryRole struct {
	ObjectID       string `json:"id"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description,omitempty"`
	RoleTemplateID string `json:"roleTemplateId"`
}

// EntraRoleDefinition represents an Entra ID role definition.
type EntraRoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	IsBuiltIn   bool   `json:"isBuiltIn,omitempty"`
	IsEnabled   bool   `json:"isEnabled,omitempty"`
}

// ConditionalAccessPolicy represents an Entra ID conditional access policy.
type ConditionalAccessPolicy struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
}

// DirectoryRoleAssignment represents an assignment of a directory role to a principal.
type DirectoryRoleAssignment struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	DirectoryScopeID string `json:"directoryScopeId,omitempty"`
}

// GroupMembership represents a membership relationship between a group and a member.
type GroupMembership struct {
	GroupID    string `json:"groupId"`
	MemberID   string `json:"memberId"`
	MemberType string `json:"memberType"`
}

// OAuth2PermissionGrant represents a delegated permission grant.
type OAuth2PermissionGrant struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	ConsentType string `json:"consentType,omitempty"`
	PrincipalID string `json:"principalId,omitempty"`
	ResourceID  string `json:"resourceId,omitempty"`
	Scope       string `json:"scope"`
}

// AppRoleAssignment represents an app role assignment to a principal.
type AppRoleAssignment struct {
	ID          string `json:"id"`
	PrincipalID string `json:"principalId"`
	ResourceID  string `json:"resourceId"`
	AppRoleID   string `json:"appRoleId"`
}

// OwnershipRelationship represents an ownership link between a principal and a resource.
type OwnershipRelationship struct {
	OwnerID      string `json:"ownerId"`
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
}

// ---------------------------------------------------------------------------
// PIM types
// ---------------------------------------------------------------------------

// PIMRoleAssignment represents a PIM (Privileged Identity Management) role assignment.
type PIMRoleAssignment struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	Scope            string `json:"scope"`
	AssignmentType   string `json:"assignmentType"`
	StartDateTime    string `json:"startDateTime,omitempty"`
	EndDateTime      string `json:"endDateTime,omitempty"`
}

// ---------------------------------------------------------------------------
// RBAC types
// ---------------------------------------------------------------------------

// RoleAssignment represents an Azure RBAC role assignment.
type RoleAssignment struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	Scope            string `json:"scope"`
	PrincipalType    string `json:"principalType,omitempty"`
	Condition        string `json:"condition,omitempty"`
}

// RoleDefinition represents an Azure RBAC role definition.
type RoleDefinition struct {
	ID          string           `json:"id"`
	RoleName    string           `json:"roleName"`
	Description string           `json:"description,omitempty"`
	RoleType    string           `json:"roleType"`
	Permissions []RolePermission `json:"permissions"`
}

// RolePermission represents a set of allowed/denied actions in a role definition.
type RolePermission struct {
	Actions        []string `json:"actions,omitempty"`
	NotActions     []string `json:"notActions,omitempty"`
	DataActions    []string `json:"dataActions,omitempty"`
	NotDataActions []string `json:"notDataActions,omitempty"`
}

// HighValueResource represents an Azure resource flagged as high-value for analysis.
type HighValueResource struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
	Reason       string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Management Group types
// ---------------------------------------------------------------------------

// ManagementGroup represents an Azure management group.
type ManagementGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
	TenantID    string `json:"tenantId,omitempty"`
}

// ManagementGroupRelationship represents a parent-child relationship in the management group hierarchy.
type ManagementGroupRelationship struct {
	ParentID  string `json:"parentId"`
	ChildID   string `json:"childId"`
	ChildType string `json:"childType"`
}

// ---------------------------------------------------------------------------
// Collection result types
// ---------------------------------------------------------------------------

// EntraIDData holds all collected Entra ID data for a tenant.
type EntraIDData struct {
	model.BaseAurelianModel

	TenantID          string                          `json:"-"`
	Users             store.Map[EntraUser]            `json:"-"`
	Groups            store.Map[EntraGroup]           `json:"-"`
	ServicePrincipals store.Map[EntraServicePrincipal] `json:"-"`
	Applications      store.Map[EntraApplication]     `json:"-"`

	Devices                    []EntraDevice              `json:"-"`
	DirectoryRoles             []DirectoryRole            `json:"-"`
	RoleDefinitions            []EntraRoleDefinition      `json:"-"`
	ConditionalAccessPolicies  []ConditionalAccessPolicy  `json:"-"`
	DirectoryRoleAssignments   []DirectoryRoleAssignment  `json:"-"`
	GroupMemberships           []GroupMembership          `json:"-"`
	OAuth2PermissionGrants     []OAuth2PermissionGrant    `json:"-"`
	AppRoleAssignments         []AppRoleAssignment        `json:"-"`
	OwnershipRelationships     []OwnershipRelationship    `json:"-"`
}

// NewEntraIDData constructs an EntraIDData from slices, populating store.Maps keyed by object ID.
func NewEntraIDData(
	tenantID string,
	users []EntraUser,
	groups []EntraGroup,
	servicePrincipals []EntraServicePrincipal,
	applications []EntraApplication,
) *EntraIDData {
	e := &EntraIDData{
		TenantID:          tenantID,
		Users:             store.NewMap[EntraUser](),
		Groups:            store.NewMap[EntraGroup](),
		ServicePrincipals: store.NewMap[EntraServicePrincipal](),
		Applications:      store.NewMap[EntraApplication](),
	}
	for _, u := range users {
		e.Users.Set(u.ObjectID, u)
	}
	for _, g := range groups {
		e.Groups.Set(g.ObjectID, g)
	}
	for _, sp := range servicePrincipals {
		e.ServicePrincipals.Set(sp.ObjectID, sp)
	}
	for _, app := range applications {
		e.Applications.Set(app.ObjectID, app)
	}
	return e
}

// entraIDDataJSON is the wire-format representation for EntraIDData.
type entraIDDataJSON struct {
	TenantID                  string                    `json:"tenantId"`
	Users                     []EntraUser               `json:"users"`
	Groups                    []EntraGroup              `json:"groups"`
	ServicePrincipals         []EntraServicePrincipal   `json:"servicePrincipals"`
	Applications              []EntraApplication        `json:"applications"`
	Devices                   []EntraDevice             `json:"devices,omitempty"`
	DirectoryRoles            []DirectoryRole           `json:"directoryRoles,omitempty"`
	RoleDefinitions           []EntraRoleDefinition     `json:"roleDefinitions,omitempty"`
	ConditionalAccessPolicies []ConditionalAccessPolicy `json:"conditionalAccessPolicies,omitempty"`
	DirectoryRoleAssignments  []DirectoryRoleAssignment `json:"directoryRoleAssignments,omitempty"`
	GroupMemberships          []GroupMembership         `json:"groupMemberships,omitempty"`
	OAuth2PermissionGrants    []OAuth2PermissionGrant   `json:"oAuth2PermissionGrants,omitempty"`
	AppRoleAssignments        []AppRoleAssignment       `json:"appRoleAssignments,omitempty"`
	OwnershipRelationships    []OwnershipRelationship   `json:"ownershipRelationships,omitempty"`
}

func (e *EntraIDData) MarshalJSON() ([]byte, error) {
	wire := entraIDDataJSON{TenantID: e.TenantID}

	e.Users.Range(func(_ string, v EntraUser) bool {
		wire.Users = append(wire.Users, v)
		return true
	})
	e.Groups.Range(func(_ string, v EntraGroup) bool {
		wire.Groups = append(wire.Groups, v)
		return true
	})
	e.ServicePrincipals.Range(func(_ string, v EntraServicePrincipal) bool {
		wire.ServicePrincipals = append(wire.ServicePrincipals, v)
		return true
	})
	e.Applications.Range(func(_ string, v EntraApplication) bool {
		wire.Applications = append(wire.Applications, v)
		return true
	})

	wire.Devices = e.Devices
	wire.DirectoryRoles = e.DirectoryRoles
	wire.RoleDefinitions = e.RoleDefinitions
	wire.ConditionalAccessPolicies = e.ConditionalAccessPolicies
	wire.DirectoryRoleAssignments = e.DirectoryRoleAssignments
	wire.GroupMemberships = e.GroupMemberships
	wire.OAuth2PermissionGrants = e.OAuth2PermissionGrants
	wire.AppRoleAssignments = e.AppRoleAssignments
	wire.OwnershipRelationships = e.OwnershipRelationships

	return json.Marshal(wire)
}

func (e *EntraIDData) UnmarshalJSON(data []byte) error {
	var wire entraIDDataJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	e.TenantID = wire.TenantID
	e.Users = store.NewMap[EntraUser]()
	e.Groups = store.NewMap[EntraGroup]()
	e.ServicePrincipals = store.NewMap[EntraServicePrincipal]()
	e.Applications = store.NewMap[EntraApplication]()

	for _, u := range wire.Users {
		e.Users.Set(u.ObjectID, u)
	}
	for _, g := range wire.Groups {
		e.Groups.Set(g.ObjectID, g)
	}
	for _, sp := range wire.ServicePrincipals {
		e.ServicePrincipals.Set(sp.ObjectID, sp)
	}
	for _, app := range wire.Applications {
		e.Applications.Set(app.ObjectID, app)
	}

	e.Devices = wire.Devices
	e.DirectoryRoles = wire.DirectoryRoles
	e.RoleDefinitions = wire.RoleDefinitions
	e.ConditionalAccessPolicies = wire.ConditionalAccessPolicies
	e.DirectoryRoleAssignments = wire.DirectoryRoleAssignments
	e.GroupMemberships = wire.GroupMemberships
	e.OAuth2PermissionGrants = wire.OAuth2PermissionGrants
	e.AppRoleAssignments = wire.AppRoleAssignments
	e.OwnershipRelationships = wire.OwnershipRelationships

	return nil
}

// PIMData holds PIM role assignment data for a tenant.
type PIMData struct {
	model.BaseAurelianModel

	ActiveAssignments   []PIMRoleAssignment `json:"activeAssignments,omitempty"`
	EligibleAssignments []PIMRoleAssignment `json:"eligibleAssignments,omitempty"`
}

// RBACData holds RBAC data for a single subscription.
type RBACData struct {
	model.BaseAurelianModel

	SubscriptionID     string                     `json:"-"`
	Assignments        []RoleAssignment           `json:"-"`
	Definitions        store.Map[RoleDefinition]  `json:"-"`
	HighValueResources []HighValueResource        `json:"-"`
}

// NewRBACData constructs an RBACData from slices, populating Definitions keyed by ID.
func NewRBACData(
	subscriptionID string,
	assignments []RoleAssignment,
	definitions []RoleDefinition,
) *RBACData {
	r := &RBACData{
		SubscriptionID: subscriptionID,
		Assignments:    assignments,
		Definitions:    store.NewMap[RoleDefinition](),
	}
	for _, d := range definitions {
		r.Definitions.Set(d.ID, d)
	}
	return r
}

// rbacDataJSON is the wire-format representation for RBACData.
type rbacDataJSON struct {
	SubscriptionID     string              `json:"subscriptionId"`
	Assignments        []RoleAssignment    `json:"assignments,omitempty"`
	Definitions        []RoleDefinition    `json:"definitions,omitempty"`
	HighValueResources []HighValueResource `json:"highValueResources,omitempty"`
}

func (r *RBACData) MarshalJSON() ([]byte, error) {
	wire := rbacDataJSON{
		SubscriptionID:     r.SubscriptionID,
		Assignments:        r.Assignments,
		HighValueResources: r.HighValueResources,
	}

	r.Definitions.Range(func(_ string, v RoleDefinition) bool {
		wire.Definitions = append(wire.Definitions, v)
		return true
	})

	return json.Marshal(wire)
}

func (r *RBACData) UnmarshalJSON(data []byte) error {
	var wire rbacDataJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	r.SubscriptionID = wire.SubscriptionID
	r.Assignments = wire.Assignments
	r.HighValueResources = wire.HighValueResources
	r.Definitions = store.NewMap[RoleDefinition]()

	for _, d := range wire.Definitions {
		r.Definitions.Set(d.ID, d)
	}

	return nil
}

// ManagementGroupData holds management group hierarchy data.
type ManagementGroupData struct {
	model.BaseAurelianModel

	Groups        []ManagementGroup             `json:"groups,omitempty"`
	Relationships []ManagementGroupRelationship `json:"relationships,omitempty"`
}

// CollectionMetadata holds metadata about a collection run.
type CollectionMetadata struct {
	TenantID  string         `json:"tenantId"`
	Timestamp string         `json:"timestamp"`
	Counts    map[string]int `json:"counts,omitempty"`
}

// AzureIAMConsolidated holds all Azure IAM data from all collectors.
type AzureIAMConsolidated struct {
	model.BaseAurelianModel

	EntraID          *EntraIDData         `json:"entraId,omitempty"`
	PIM              *PIMData             `json:"pim,omitempty"`
	RBAC             []*RBACData          `json:"rbac,omitempty"`
	ManagementGroups *ManagementGroupData `json:"managementGroups,omitempty"`
	Metadata         *CollectionMetadata  `json:"metadata,omitempty"`
}
