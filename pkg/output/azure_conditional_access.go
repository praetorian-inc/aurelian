package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// AzureConditionalAccessPolicy represents an Azure AD Conditional Access Policy.
type AzureConditionalAccessPolicy struct {
	model.BaseAurelianModel

	ID               string                         `json:"id"`
	DisplayName      string                         `json:"display_name"`
	State            string                         `json:"state"`
	TemplateID       string                         `json:"template_id,omitempty"`
	CreatedDateTime  string                         `json:"created_date_time,omitempty"`
	ModifiedDateTime string                         `json:"modified_date_time,omitempty"`
	Conditions       *ConditionalAccessConditions   `json:"conditions,omitempty"`
	GrantControls    map[string]any                 `json:"grant_controls,omitempty"`
	SessionControls  map[string]any                 `json:"session_controls,omitempty"`

	ResolvedUsers        map[string]ResolvedEntity `json:"resolved_users,omitempty"`
	ResolvedGroups       map[string]ResolvedEntity `json:"resolved_groups,omitempty"`
	ResolvedApplications map[string]ResolvedEntity `json:"resolved_applications,omitempty"`
	ResolvedRoles        map[string]ResolvedEntity `json:"resolved_roles,omitempty"`
}

// ResolvedEntity represents a UUID resolved to human-readable information.
type ResolvedEntity struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description,omitempty"`
	ExtraInfo   map[string]string `json:"extra_info,omitempty"`
}

// ConditionalAccessConditions contains the conditions under which a policy applies.
type ConditionalAccessConditions struct {
	Users            *ConditionalAccessUsers        `json:"users,omitempty"`
	Applications     *ConditionalAccessApplications `json:"applications,omitempty"`
	Locations        map[string]any                 `json:"locations,omitempty"`
	Platforms        map[string]any                 `json:"platforms,omitempty"`
	ClientAppTypes   []string                       `json:"client_app_types,omitempty"`
	SignInRiskLevels []string                       `json:"sign_in_risk_levels,omitempty"`
	UserRiskLevels   []string                       `json:"user_risk_levels,omitempty"`
}

// ConditionalAccessUsers describes user/group/role conditions.
type ConditionalAccessUsers struct {
	IncludeUsers                 []string       `json:"include_users,omitempty"`
	ExcludeUsers                 []string       `json:"exclude_users,omitempty"`
	IncludeGroups                []string       `json:"include_groups,omitempty"`
	ExcludeGroups                []string       `json:"exclude_groups,omitempty"`
	IncludeRoles                 []string       `json:"include_roles,omitempty"`
	ExcludeRoles                 []string       `json:"exclude_roles,omitempty"`
	IncludeGuestsOrExternalUsers map[string]any `json:"include_guests_or_external_users,omitempty"`
	ExcludeGuestsOrExternalUsers map[string]any `json:"exclude_guests_or_external_users,omitempty"`
}

// ConditionalAccessApplications describes application conditions.
type ConditionalAccessApplications struct {
	IncludeApplications []string       `json:"include_applications,omitempty"`
	ExcludeApplications []string       `json:"exclude_applications,omitempty"`
	IncludeUserActions  []string       `json:"include_user_actions,omitempty"`
	ApplicationFilter   map[string]any `json:"application_filter,omitempty"`
}
