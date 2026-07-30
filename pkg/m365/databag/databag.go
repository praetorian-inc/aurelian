// Package databag provides a shared data structure for M365 CIS checks.
// The DataCollector pre-fetches all data for a service area into the DataBag,
// minimizing API calls and avoiding rate limits.
package databag

// M365DataBag holds all pre-fetched M365 data needed by CIS checks.
type M365DataBag struct {
	TenantID     string
	TenantDomain string

	// Entra ID data
	ConditionalAccessPolicies []ConditionalAccessPolicy
	AuthorizationPolicy       *AuthorizationPolicy
	DirectoryRoles            []DirectoryRole
	Users                     []User
	Groups                    []Group
	AuthMethodsPolicy         *AuthMethodsPolicy
	AdminConsentPolicy        *AdminConsentPolicy
	OnPremSyncSettings        *OnPremSyncSettings
	ExternalIdentityPolicy    *ExternalIdentityPolicy
	AdminPortalSettings       *AdminPortalSettings

	// Per-user MFA registration details (from reports/credentialUserRegistrationDetails)
	CredentialUserRegistrationDetails []CredentialUserRegistrationDetail

	// Admin Center data
	OrganizationSettings *OrganizationSettings
	PasswordPolicies     *PasswordPolicies
	FormsSettings        *FormsSettings
	BookingsSettings     *BookingsSettings

	// Defender data (Graph API portion)
	SafeLinksPolicy      []SafeLinksPolicy
	SafeAttachmentPolicy []SafeAttachmentPolicy
	MalwareFilterPolicy  []MalwareFilterPolicy
	AntiPhishingPolicy   []AntiPhishingPolicy
	DKIMConfigs          []DKIMConfig
	ConnectionFilter     *ConnectionFilterPolicy
	AntispamPolicies     []AntispamPolicy
	OutboundSpamPolicies []OutboundSpamPolicy
	ATPConfig            *ATPConfig
	ZAPConfig            *ZAPConfig
	ChatReportPolicy     *ChatReportPolicy
	DefenderIdentityHealthIssues []DefenderIdentityHealthIssue
	ExposedCredentials   []ExposedCredential

	// Defender additional data
	SpamNotificationPolicy *SpamNotificationPolicy
	DomainSPFRecords       []DomainSPFRecord
	DomainDMARCRecords     []DomainDMARCRecord

	// Purview additional data
	DLPPolicies       []DLPPolicy
	SensitivityLabels []SensitivityLabel

	// Intune data
	IntuneDeviceCompliance   *IntuneDeviceComplianceSettings
	IntuneEnrollmentRestriction *IntuneEnrollmentRestriction

	// Entra additional data
	DeviceRegistrationPolicy *DeviceRegistrationPolicy
	LAPSSettings             *LAPSSettings
	AccessReviews            []AccessReview

	// PowerShell-collected data
	ExchangeConfig          *ExchangeOrgConfig
	TransportRules          []TransportRule
	MailboxAuditConfig      []MailboxAuditConfig
	RoleAssignmentPolicies  []RoleAssignmentPolicy
	MailboxPolicies         []MailboxPolicy
	ExternalEmailTagging    *ExternalEmailTagging
	SharedMailboxes         []SharedMailbox
	TeamsMeetingPolicy      *TeamsMeetingPolicy
	TeamsMessagingPolicy    *TeamsMessagingPolicy
	TeamsExternalAccess     *TeamsExternalAccessPolicy
	TeamsClientConfig       *TeamsClientConfig
	TeamsSecurityReporting  *TeamsSecurityReporting
	SharePointTenant        *SharePointTenantConfig
	PurviewAuditConfig      *PurviewAuditConfig
}

// New creates a new M365DataBag with the given tenant information.
func New(tenantID, tenantDomain string) *M365DataBag {
	return &M365DataBag{
		TenantID:     tenantID,
		TenantDomain: tenantDomain,
	}
}
