package databag

// ConditionalAccessPolicy represents an Entra ID Conditional Access policy.
type ConditionalAccessPolicy struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"` // enabled, disabled, enabledForReportingButNotEnforced

	// Conditions
	IncludeUsers  []string `json:"includeUsers,omitempty"`
	ExcludeUsers  []string `json:"excludeUsers,omitempty"`
	IncludeGroups []string `json:"includeGroups,omitempty"`
	ExcludeGroups []string `json:"excludeGroups,omitempty"`
	IncludeRoles  []string `json:"includeRoles,omitempty"`
	ExcludeRoles  []string `json:"excludeRoles,omitempty"`

	// Application conditions
	IncludeApplications []string `json:"includeApplications,omitempty"`
	ExcludeApplications []string `json:"excludeApplications,omitempty"`

	// User action conditions (e.g., "registerSecurityInformation")
	IncludeUserActions []string `json:"includeUserActions,omitempty"`

	// Client app types
	ClientAppTypes []string `json:"clientAppTypes,omitempty"`

	// Risk levels
	SignInRiskLevels []string `json:"signInRiskLevels,omitempty"`
	UserRiskLevels   []string `json:"userRiskLevels,omitempty"`

	// Transfer methods (e.g., "deviceCodeFlow", "authenticationTransfer")
	TransferMethods []string `json:"transferMethods,omitempty"`

	// Grant controls
	GrantOperator           string   `json:"grantOperator,omitempty"`
	BuiltInControls         []string `json:"builtInControls,omitempty"`
	AuthenticationStrength  *AuthenticationStrengthPolicy `json:"authenticationStrength,omitempty"`

	// Session controls
	SignInFrequencyValue    *int32 `json:"signInFrequencyValue,omitempty"`
	SignInFrequencyUnit     string `json:"signInFrequencyUnit,omitempty"` // hours, days
	SignInFrequencyEnabled  bool   `json:"signInFrequencyEnabled,omitempty"`
	PersistentBrowserMode   string `json:"persistentBrowserMode,omitempty"`
}

// AuthenticationStrengthPolicy represents the authentication strength required by a CA policy.
type AuthenticationStrengthPolicy struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	// AllowedCombinations lists the allowed method combinations (e.g., "fido2", "windowsHelloForBusiness")
	AllowedCombinations []string `json:"allowedCombinations,omitempty"`
}

// AuthorizationPolicy represents the tenant authorization policy.
type AuthorizationPolicy struct {
	ID                                     string `json:"id"`
	AllowInvitesFrom                       string `json:"allowInvitesFrom"`
	AllowedToSignUpEmailBasedSubscriptions bool   `json:"allowedToSignUpEmailBasedSubscriptions"`
	AllowedToUseSSPR                       bool   `json:"allowedToUseSSPR"`
	AllowEmailVerifiedUsersToJoinOrganization bool `json:"allowEmailVerifiedUsersToJoinOrganization"`
	BlockMsolPowerShell                    bool   `json:"blockMsolPowerShell"`
	DefaultUserRolePermissions             *DefaultUserRolePermissions `json:"defaultUserRolePermissions,omitempty"`
	GuestUserRoleID                        string `json:"guestUserRoleId"`
}

// DefaultUserRolePermissions represents default user role permissions.
type DefaultUserRolePermissions struct {
	AllowedToCreateApps             bool `json:"allowedToCreateApps"`
	AllowedToCreateSecurityGroups   bool `json:"allowedToCreateSecurityGroups"`
	AllowedToCreateTenants          bool `json:"allowedToCreateTenants"`
	AllowedToReadBitlockerKeysForOwnedDevice bool `json:"allowedToReadBitlockerKeysForOwnedDevice"`
	AllowedToReadOtherUsers         bool `json:"allowedToReadOtherUsers"`
	// PermissionGrantPoliciesAssigned controls user consent workflow.
	// Empty or "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" means user consent is allowed.
	PermissionGrantPoliciesAssigned []string `json:"permissionGrantPoliciesAssigned,omitempty"`
}

// DirectoryRole represents an Entra ID directory role.
type DirectoryRole struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	RoleTemplateID string `json:"roleTemplateId"`
	Members     []string `json:"members,omitempty"` // member user IDs
}

// User represents an Entra ID user.
type User struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"displayName"`
	UserPrincipalName string   `json:"userPrincipalName"`
	AccountEnabled    bool     `json:"accountEnabled"`
	UserType          string   `json:"userType"` // Member, Guest
	OnPremisesSyncEnabled *bool `json:"onPremisesSyncEnabled,omitempty"`
	AssignedLicenses  []string `json:"assignedLicenses,omitempty"`
	// Authentication methods registered by this user (e.g., "microsoftAuthenticator", "fido2", "sms", "phone")
	AuthMethods       []string `json:"authMethods,omitempty"`
	// IsMFACapable indicates whether the user has registered at least one MFA method.
	IsMFACapable      bool     `json:"isMFACapable,omitempty"`
}

// GroupMembershipRule represents a dynamic group membership rule.
type GroupMembershipRule struct {
	GroupID    string `json:"groupId"`
	GroupName  string `json:"groupName"`
	RuleExpression string `json:"ruleExpression"`
}

// Group represents an Entra ID group.
type Group struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName"`
	GroupTypes            []string `json:"groupTypes,omitempty"` // "DynamicMembership", "Unified"
	Visibility            string   `json:"visibility"`           // Public, Private, HiddenMembership
	MembershipRule        string   `json:"membershipRule,omitempty"`
	MembershipRuleProcessingState string `json:"membershipRuleProcessingState,omitempty"` // On, Paused
}

// AuthMethodsPolicy represents the authentication methods policy.
type AuthMethodsPolicy struct {
	ID                     string                    `json:"id"`
	RegistrationEnforcement *RegistrationEnforcement  `json:"registrationEnforcement,omitempty"`
	AuthMethodConfigs       []AuthMethodConfiguration `json:"authMethodConfigs,omitempty"`
}

// RegistrationEnforcement represents MFA registration enforcement.
type RegistrationEnforcement struct {
	AuthenticationMethodsRegistrationCampaign *MFARegistrationCampaign `json:"authenticationMethodsRegistrationCampaign,omitempty"`
}

// MFARegistrationCampaign represents the MFA registration campaign settings.
type MFARegistrationCampaign struct {
	State string `json:"state"` // enabled, disabled
}

// AuthMethodConfiguration represents a single auth method configuration.
type AuthMethodConfiguration struct {
	ID    string `json:"id"`
	State string `json:"state"` // enabled, disabled
	// Method-specific: SMS, Voice, Email, FIDO2, etc.
	MethodType string `json:"methodType"`
}

// AdminConsentPolicy represents the admin consent request policy.
type AdminConsentPolicy struct {
	IsEnabled        bool `json:"isEnabled"`
	NotifyReviewers  bool `json:"notifyReviewers"`
	RemindersEnabled bool `json:"remindersEnabled"`
}

// OnPremSyncSettings represents on-premises directory sync settings.
type OnPremSyncSettings struct {
	OnPremisesSyncEnabled          bool `json:"onPremisesSyncEnabled"`
	PasswordHashSyncEnabled        bool `json:"passwordHashSyncEnabled"`
	SeamlessSingleSignOnEnabled    bool `json:"seamlessSingleSignOnEnabled"`
	PassThroughAuthenticationEnabled bool `json:"passThroughAuthenticationEnabled"`
}

// CredentialUserRegistrationDetail represents per-user MFA/SSPR registration status
// from the reports/credentialUserRegistrationDetails endpoint.
type CredentialUserRegistrationDetail struct {
	UserPrincipalName string   `json:"userPrincipalName"`
	IsMfaRegistered   bool     `json:"isMfaRegistered"`
	IsMfaCapable      bool     `json:"isMfaCapable"`
	AuthMethods       []string `json:"authMethods,omitempty"`
}

// ExternalIdentityPolicy represents cross-tenant access / external collaboration settings.
type ExternalIdentityPolicy struct {
	AllowInvitesFrom string `json:"allowInvitesFrom"` // everyone, adminsAndGuestInviters, adminsGuestInvitersAndAllMembers, none
}

// AdminPortalSettings represents admin portal access restrictions (Azure portal, M365 admin center, etc.).
type AdminPortalSettings struct {
	RestrictNonAdminUsers bool `json:"restrictNonAdminUsers"` // true = non-admin users cannot access admin portals
}

// OrganizationSettings represents M365 admin center organization settings.
type OrganizationSettings struct {
	PasswordExpirationDays      int  `json:"passwordExpirationDays"`
	PasswordNeverExpires        bool `json:"passwordNeverExpires"`
	CalendarSharingExternal     bool `json:"calendarSharingExternal"`
	CustomerLockboxEnabled      bool `json:"customerLockboxEnabled"`
	IdleSessionTimeout          int  `json:"idleSessionTimeout"` // minutes
	ReleasePreferencesEnabled   bool `json:"releasePreferencesEnabled"`
	UserOwnedAppsEnabled        bool `json:"userOwnedAppsEnabled"`
	ThirdPartyStorageRestricted bool `json:"thirdPartyStorageRestricted"`
}

// FormsSettings represents Microsoft Forms settings.
type FormsSettings struct {
	InternalPhishingProtection bool `json:"internalPhishingProtection"`
}

// BookingsSettings represents Microsoft Bookings settings.
type BookingsSettings struct {
	SharedBookingsRestricted bool `json:"sharedBookingsRestricted"`
}

// PasswordPolicies represents the tenant password policies.
type PasswordPolicies struct {
	BannedPasswordsEnabled bool `json:"bannedPasswordsEnabled"`
	CustomBannedPasswords  []string `json:"customBannedPasswords,omitempty"`
	LockoutThreshold       int  `json:"lockoutThreshold"`
	LockoutDuration        int  `json:"lockoutDuration"` // seconds
	EnableBannedPasswordCheckOnPrem bool `json:"enableBannedPasswordCheckOnPrem"`
}

// SafeLinksPolicy represents a Defender Safe Links policy.
type SafeLinksPolicy struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	IsEnabled           bool   `json:"isEnabled"`
	DoNotAllowClickThrough bool `json:"doNotAllowClickThrough"`
	ScanUrls            bool   `json:"scanUrls"`
	EnableForInternalSenders bool `json:"enableForInternalSenders"`
}

// SafeAttachmentPolicy represents a Defender Safe Attachments policy.
type SafeAttachmentPolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsEnabled bool   `json:"isEnabled"`
	Action    string `json:"action"` // Block, Replace, DynamicDelivery
}

// MalwareFilterPolicy represents a Defender malware filter policy.
type MalwareFilterPolicy struct {
	ID                                     string   `json:"id"`
	Name                                   string   `json:"name"`
	IsEnabled                              bool     `json:"isEnabled"`
	EnableFileFilter                       bool     `json:"enableFileFilter"`
	FileTypes                              []string `json:"fileTypes,omitempty"`
	ZapEnabled                             bool     `json:"zapEnabled"`
	EnableInternalSenderAdminNotifications bool     `json:"enableInternalSenderAdminNotifications"`
}

// AntiPhishingPolicy represents a Defender anti-phishing policy.
type AntiPhishingPolicy struct {
	ID                                  string `json:"id"`
	Name                                string `json:"name"`
	IsEnabled                           bool   `json:"isEnabled"`
	EnableMailboxIntelligence           bool   `json:"enableMailboxIntelligence"`
	EnableMailboxIntelligenceProtection bool   `json:"enableMailboxIntelligenceProtection"`
	EnableSpoofIntelligence             bool   `json:"enableSpoofIntelligence"`
	EnableTargetedUserProtection        bool   `json:"enableTargetedUserProtection"`
	EnableTargetedDomainProtection      bool   `json:"enableTargetedDomainProtection"`
	EnableOrganizationDomainsProtection bool   `json:"enableOrganizationDomainsProtection"`
	PhishThresholdLevel                 int    `json:"phishThresholdLevel"`
}

// DKIMConfig represents DKIM signing configuration for a domain.
type DKIMConfig struct {
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
}

// ConnectionFilterPolicy represents the Exchange connection filter policy.
type ConnectionFilterPolicy struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	IPAllowList    []string `json:"ipAllowList,omitempty"`
	IPBlockList    []string `json:"ipBlockList,omitempty"`
	EnableSafeList bool     `json:"enableSafeList"`
}

// AntispamPolicy represents an inbound anti-spam policy.
type AntispamPolicy struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	IsEnabled                bool     `json:"isEnabled"`
	AllowedSenderDomains     []string `json:"allowedSenderDomains,omitempty"`
	AllowedSenders           []string `json:"allowedSenders,omitempty"`
	SpamAction               string   `json:"spamAction"`
	HighConfidenceSpamAction string   `json:"highConfidenceSpamAction"`
}

// OutboundSpamPolicy represents an outbound spam filter policy.
type OutboundSpamPolicy struct {
	ID                                        string   `json:"id"`
	Name                                      string   `json:"name"`
	IsEnabled                                 bool     `json:"isEnabled"`
	BccSuspiciousOutboundMail                 bool     `json:"bccSuspiciousOutboundMail"`
	BccSuspiciousOutboundAdditionalRecipients []string `json:"bccSuspiciousOutboundAdditionalRecipients,omitempty"`
	NotifyOutboundSpam                        bool     `json:"notifyOutboundSpam"`
	NotifyOutboundSpamRecipients              []string `json:"notifyOutboundSpamRecipients,omitempty"`
	AutoForwardingMode                        string   `json:"autoForwardingMode"` // Automatic, Off, On
}

// ATPConfig represents Advanced Threat Protection configuration for SPO/OneDrive/Teams.
type ATPConfig struct {
	EnableATPForSPOTeamsODB bool `json:"enableATPForSPOTeamsODB"`
	EnableSafeDocs         bool `json:"enableSafeDocs"`
	AllowSafeDocsOpen      bool `json:"allowSafeDocsOpen"`
}

// ZAPConfig represents Zero-hour Auto Purge configuration.
type ZAPConfig struct {
	ZapEnabled      bool `json:"zapEnabled"`
	TeamsZapEnabled bool `json:"teamsZapEnabled"`
}

// ChatReportPolicy represents a Teams chat reporting/abuse policy.
type ChatReportPolicy struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	IsEnabled            bool   `json:"isEnabled"`
	ReportToSecurityTeam bool   `json:"reportToSecurityTeam"`
}

// DefenderIdentityHealthIssue represents an unresolved Defender for Identity health issue.
type DefenderIdentityHealthIssue struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"` // High, Medium, Low
	Status        string `json:"status"`   // Open, Closed, Suppressed
	DomainName    string `json:"domainName"`
	SensorDNSName string `json:"sensorDnsName"`
}

// ExposedCredential represents a privileged user with exposed credentials.
type ExposedCredential struct {
	UserID            string `json:"userId"`
	UserPrincipalName string `json:"userPrincipalName"`
	ExposureType      string `json:"exposureType"` // e.g., ClearTextPassword, NtlmHash
	Source            string `json:"source"`
}

// ExchangeOrgConfig represents Exchange Online organization configuration.
type ExchangeOrgConfig struct {
	AuditDisabled                        bool `json:"auditDisabled"`
	OAuth2ClientProfileEnabled           bool `json:"oAuth2ClientProfileEnabled"`
	ModernAuthEnabled                    bool `json:"modernAuthEnabled"`
	MapiHttpEnabled                      bool `json:"mapiHttpEnabled"`
	SmtpClientAuthenticationDisabled     bool `json:"smtpClientAuthenticationDisabled"`
	MailTipsAllTipsEnabled               bool `json:"mailTipsAllTipsEnabled"`
	MailTipsExternalRecipientsTipsEnabled bool `json:"mailTipsExternalRecipientsTipsEnabled"`
	MailTipsGroupMetricsEnabled          bool `json:"mailTipsGroupMetricsEnabled"`
	MailTipsLargeAudienceThreshold       int  `json:"mailTipsLargeAudienceThreshold"`
	DirectSendRestricted                 bool `json:"directSendRestricted"`
}

// TransportRule represents an Exchange transport rule.
type TransportRule struct {
	Name   string `json:"name"`
	State  string `json:"state"` // Enabled, Disabled
	Mode   string `json:"mode"`
	// Rule conditions
	SenderDomainIs            []string `json:"senderDomainIs,omitempty"`
	RedirectMessageTo         []string `json:"redirectMessageTo,omitempty"`
	RouteMessageOutboundConnector string `json:"routeMessageOutboundConnector,omitempty"`
	SetHeaderName             string   `json:"setHeaderName,omitempty"`
	SetHeaderValue            string   `json:"setHeaderValue,omitempty"`
	SenderDomainIsWhitelisted bool     `json:"senderDomainIsWhitelisted,omitempty"`
	SetSCL                    *int     `json:"setSCL,omitempty"`
}

// RoleAssignmentPolicy represents an Exchange role assignment policy.
type RoleAssignmentPolicy struct {
	Name          string   `json:"name"`
	IsDefault     bool     `json:"isDefault"`
	AssignedRoles []string `json:"assignedRoles,omitempty"`
}

// MailboxPolicy represents an OWA mailbox policy.
type MailboxPolicy struct {
	Name                                string `json:"name"`
	ThirdPartyFileProvidersEnabled      bool   `json:"thirdPartyFileProvidersEnabled"`
	AdditionalStorageProvidersAvailable bool   `json:"additionalStorageProvidersAvailable"`
}

// ExternalEmailTagging represents the external email tagging configuration.
type ExternalEmailTagging struct {
	Enabled bool `json:"enabled"`
}

// SharedMailbox represents a shared mailbox configuration.
type SharedMailbox struct {
	Identity       string `json:"identity"`
	SignInEnabled  bool   `json:"signInEnabled"`
	AccountEnabled bool   `json:"accountEnabled"`
}

// MailboxAuditConfig represents mailbox audit configuration.
type MailboxAuditConfig struct {
	Identity          string   `json:"identity"`
	AuditEnabled      bool     `json:"auditEnabled"`
	AuditLogAgeLimit  string   `json:"auditLogAgeLimit"`
	AuditBypassEnabled bool    `json:"auditBypassEnabled"`
	AuditAdmin        []string `json:"auditAdmin,omitempty"`
	AuditDelegate     []string `json:"auditDelegate,omitempty"`
	AuditOwner        []string `json:"auditOwner,omitempty"`
}

// TeamsMeetingPolicy represents Teams meeting policy settings.
type TeamsMeetingPolicy struct {
	AllowAnonymousUsersToJoinMeeting          bool   `json:"allowAnonymousUsersToJoinMeeting"`
	AllowAnonymousUsersToStartMeeting         bool   `json:"allowAnonymousUsersToStartMeeting"`
	AllowExternalParticipantGiveRequestControl bool   `json:"allowExternalParticipantGiveRequestControl"`
	AutoAdmittedUsers                         string `json:"autoAdmittedUsers"`
	AllowCloudRecording                       bool   `json:"allowCloudRecording"`
	AllowPSTNUsersToBypassLobby               bool   `json:"allowPSTNUsersToBypassLobby"`
	DesignatedPresenterRoleMode               string `json:"designatedPresenterRoleMode"`
	MeetingChatEnabledType                    string `json:"meetingChatEnabledType"`
	AutoRecording                             bool   `json:"autoRecording"`
}

// TeamsExternalAccessPolicy represents Teams external access settings.
type TeamsExternalAccessPolicy struct {
	AllowTeamsConsumer         bool     `json:"allowTeamsConsumer"`
	AllowTeamsConsumerInbound  bool     `json:"allowTeamsConsumerInbound"`
	AllowFederatedUsers        bool     `json:"allowFederatedUsers"`
	AllowedDomains             []string `json:"allowedDomains,omitempty"`
	BlockedDomains             []string `json:"blockedDomains,omitempty"`
	AllowPublicUsers           bool     `json:"allowPublicUsers"`
}

// TeamsClientConfig represents Teams client configuration.
type TeamsClientConfig struct {
	AllowDropBox        bool     `json:"allowDropBox"`
	AllowBox            bool     `json:"allowBox"`
	AllowGoogleDrive    bool     `json:"allowGoogleDrive"`
	AllowShareFile      bool     `json:"allowShareFile"`
	AllowEgnyte         bool     `json:"allowEgnyte"`
	AllowEmailIntoChannel bool   `json:"allowEmailIntoChannel"`
	RestrictedSenderList []string `json:"restrictedSenderList,omitempty"`
}

// TeamsSecurityReporting represents Teams security and reporting settings.
type TeamsSecurityReporting struct {
	ReportSecurityConcernsEnabled bool `json:"reportSecurityConcernsEnabled"`
}

// TeamsMessagingPolicy represents Teams messaging policy settings.
type TeamsMessagingPolicy struct {
	AllowOwnerDeleteMessage bool `json:"allowOwnerDeleteMessage"`
	AllowUserEditMessage    bool `json:"allowUserEditMessage"`
	AllowUserDeleteMessage  bool `json:"allowUserDeleteMessage"`
	AllowUserChat           bool `json:"allowUserChat"`
	AllowGiphy              bool `json:"allowGiphy"`
}

// SharePointTenantConfig represents SharePoint Online tenant configuration.
type SharePointTenantConfig struct {
	SharingCapability                         string   `json:"sharingCapability"`
	RequireAcceptingAccountMatchInvitedAccount bool    `json:"requireAcceptingAccountMatchInvitedAccount"`
	PreventExternalUsersFromResharing         bool     `json:"preventExternalUsersFromResharing"`
	OneDriveBlockGuestSharing                 bool     `json:"oneDriveBlockGuestSharing"`
	LegacyAuthProtocolsEnabled                bool     `json:"legacyAuthProtocolsEnabled"`
	SharingDomainRestrictionMode              string   `json:"sharingDomainRestrictionMode"` // None, AllowList, BlockList
	SharingAllowedDomainList                  []string `json:"sharingAllowedDomainList,omitempty"`
	SharingBlockedDomainList                  []string `json:"sharingBlockedDomainList,omitempty"`
	DefaultSharingLinkType                    string   `json:"defaultSharingLinkType"` // None, Direct, Internal, AnonymousAccess
	IsUnmanagedSyncClientForTenantRestricted  bool     `json:"isUnmanagedSyncClientForTenantRestricted"`
	OneDriveSharingCapability                 string   `json:"oneDriveSharingCapability"` // Disabled, ExternalUserSharingOnly, ExternalUserAndGuestSharing, ExistingExternalUserSharingOnly
	ExternalUserExpireInDays                  int      `json:"externalUserExpireInDays"`
	EmailAttestationReAuthDays                int      `json:"emailAttestationReAuthDays"`
	DefaultLinkPermission                     string   `json:"defaultLinkPermission"` // View, Edit
	DisallowInfectedFileDownload              bool     `json:"disallowInfectedFileDownload"`
}

// PurviewAuditConfig represents Purview unified audit log configuration.
type PurviewAuditConfig struct {
	UnifiedAuditLogEnabled bool `json:"unifiedAuditLogEnabled"`
}

// SpamNotificationPolicy represents spam notification settings for administrators.
type SpamNotificationPolicy struct {
	NotifyAdmins bool `json:"notifyAdmins"`
}

// DomainSPFRecord represents SPF record status for an Exchange domain.
type DomainSPFRecord struct {
	Domain string `json:"domain"`
	HasSPF bool   `json:"hasSPF"`
}

// DomainDMARCRecord represents DMARC record status for an Exchange domain.
type DomainDMARCRecord struct {
	Domain   string `json:"domain"`
	HasDMARC bool   `json:"hasDMARC"`
}

// DLPPolicy represents a Data Loss Prevention policy.
type DLPPolicy struct {
	IsEnabled    bool `json:"isEnabled"`
	TeamsEnabled bool `json:"teamsEnabled"`
}

// SensitivityLabel represents an Information Protection sensitivity label.
type SensitivityLabel struct {
	Published bool `json:"published"`
}

// IntuneDeviceComplianceSettings represents Intune device compliance policy settings.
type IntuneDeviceComplianceSettings struct {
	MarkDevicesNonCompliant bool `json:"markDevicesNonCompliant"`
}

// IntuneEnrollmentRestriction represents Intune enrollment restriction settings.
type IntuneEnrollmentRestriction struct {
	PersonalDeviceEnrollmentBlocked bool `json:"personalDeviceEnrollmentBlocked"`
}

// DeviceRegistrationPolicy represents Entra device registration policy settings.
type DeviceRegistrationPolicy struct {
	AllUsersCanJoin      bool `json:"allUsersCanJoin"`
	MaxDevicesPerUser    int  `json:"maxDevicesPerUser"`
	GlobalAdminAsLocalAdmin bool `json:"globalAdminAsLocalAdmin"`
	AdditionalLocalAdmins   bool `json:"additionalLocalAdmins"`
}

// LAPSSettings represents Local Administrator Password Solution settings.
type LAPSSettings struct {
	Enabled bool `json:"enabled"`
}

// AccessReview represents an access review configuration.
type AccessReview struct {
	Enabled bool   `json:"enabled"`
	Scope   string `json:"scope"` // e.g., "Guest"
}
