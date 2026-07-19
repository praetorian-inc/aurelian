package collectors

import (
	"os/exec"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPowerShellCollector_Available_WithPwsh(t *testing.T) {
	// If pwsh is installed on the system, Available() should return true.
	// If not, we test with a known-available binary as a stand-in.
	_, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not found on PATH, skipping availability test")
	}

	c := NewPowerShellCollector("pwsh")
	assert.True(t, c.Available(), "Expected Available() to return true when pwsh is on PATH")
}

func TestPowerShellCollector_NotAvailable(t *testing.T) {
	c := NewPowerShellCollector("/nonexistent/path/to/pwsh")
	assert.False(t, c.Available(), "Expected Available() to return false for nonexistent path")
}

func TestPowerShellCollector_NotAvailable_BadName(t *testing.T) {
	c := NewPowerShellCollector("definitely-not-a-real-binary-xyz123")
	assert.False(t, c.Available(), "Expected Available() to return false for nonexistent binary name")
}

func TestPowerShellCollector_DefaultPath(t *testing.T) {
	c := NewPowerShellCollector("")
	assert.Equal(t, "pwsh", c.pwshPath, "Expected default pwshPath to be 'pwsh'")
}

func TestParseExchangeJSON(t *testing.T) {
	sampleJSON := []byte(`{
		"OrgConfig": {
			"auditDisabled": false,
			"oAuth2ClientProfileEnabled": true,
			"modernAuthEnabled": true,
			"mapiHttpEnabled": true,
			"smtpClientAuthenticationDisabled": true,
			"mailTipsAllTipsEnabled": true,
			"mailTipsExternalRecipientsTipsEnabled": true,
			"mailTipsGroupMetricsEnabled": true,
			"mailTipsLargeAudienceThreshold": 25,
			"directSendRestricted": false
		},
		"TransportRules": [
			{
				"name": "Block External Forwarding",
				"state": "Enabled",
				"mode": "Enforce",
				"setHeaderName": "X-MS-Exchange-Organization-AutoForwardEnabled",
				"setHeaderValue": "false"
			}
		],
		"MailboxAuditConfigs": [
			{
				"identity": "user@contoso.com",
				"auditEnabled": true,
				"auditLogAgeLimit": "90.00:00:00",
				"auditBypassEnabled": false,
				"auditAdmin": ["Update", "Move", "MoveToDeletedItems"],
				"auditDelegate": ["Update", "Move"],
				"auditOwner": ["Update", "Move"]
			}
		],
		"RoleAssignmentPolicies": [
			{
				"name": "Default Role Assignment Policy",
				"isDefault": true,
				"assignedRoles": ["MyBaseOptions", "MyContactInformation"]
			}
		],
		"MailboxPolicies": [
			{
				"name": "OwaMailboxPolicy-Default",
				"thirdPartyFileProvidersEnabled": false,
				"additionalStorageProvidersAvailable": false
			}
		],
		"SharedMailboxes": [
			{
				"identity": "shared@contoso.com",
				"signInEnabled": false,
				"accountEnabled": false
			}
		],
		"ExternalInOutlook": {
			"enabled": true
		}
	}`)

	bag := databag.New("test-tenant", "contoso.com")
	err := parseExchangeJSON(sampleJSON, bag)
	require.NoError(t, err)

	// Verify OrgConfig
	require.NotNil(t, bag.ExchangeConfig)
	assert.False(t, bag.ExchangeConfig.AuditDisabled)
	assert.True(t, bag.ExchangeConfig.SmtpClientAuthenticationDisabled)
	assert.True(t, bag.ExchangeConfig.MailTipsAllTipsEnabled)
	assert.Equal(t, 25, bag.ExchangeConfig.MailTipsLargeAudienceThreshold)

	// Verify TransportRules
	require.Len(t, bag.TransportRules, 1)
	assert.Equal(t, "Block External Forwarding", bag.TransportRules[0].Name)
	assert.Equal(t, "Enabled", bag.TransportRules[0].State)

	// Verify MailboxAuditConfigs
	require.Len(t, bag.MailboxAuditConfig, 1)
	assert.True(t, bag.MailboxAuditConfig[0].AuditEnabled)
	assert.Equal(t, "90.00:00:00", bag.MailboxAuditConfig[0].AuditLogAgeLimit)

	// Verify RoleAssignmentPolicies
	require.Len(t, bag.RoleAssignmentPolicies, 1)
	assert.True(t, bag.RoleAssignmentPolicies[0].IsDefault)

	// Verify MailboxPolicies
	require.Len(t, bag.MailboxPolicies, 1)
	assert.False(t, bag.MailboxPolicies[0].ThirdPartyFileProvidersEnabled)

	// Verify SharedMailboxes
	require.Len(t, bag.SharedMailboxes, 1)
	assert.False(t, bag.SharedMailboxes[0].SignInEnabled)

	// Verify ExternalEmailTagging
	require.NotNil(t, bag.ExternalEmailTagging)
	assert.True(t, bag.ExternalEmailTagging.Enabled)
}

func TestParseTeamsJSON(t *testing.T) {
	sampleJSON := []byte(`{
		"MeetingPolicy": {
			"allowAnonymousUsersToJoinMeeting": false,
			"allowAnonymousUsersToStartMeeting": false,
			"allowExternalParticipantGiveRequestControl": false,
			"autoAdmittedUsers": "EveryoneInCompanyExcludingGuests",
			"allowCloudRecording": true,
			"allowPSTNUsersToBypassLobby": false,
			"designatedPresenterRoleMode": "OrganizerOnlyUserOverride",
			"meetingChatEnabledType": "Enabled",
			"autoRecording": false
		},
		"ExternalAccess": {
			"allowTeamsConsumer": false,
			"allowTeamsConsumerInbound": false,
			"allowFederatedUsers": true,
			"allowedDomains": ["partner.com"],
			"blockedDomains": [],
			"allowPublicUsers": false
		},
		"ClientConfig": {
			"allowDropBox": false,
			"allowBox": false,
			"allowGoogleDrive": false,
			"allowShareFile": false,
			"allowEgnyte": false,
			"allowEmailIntoChannel": true,
			"restrictedSenderList": []
		},
		"MessagingPolicy": {
			"allowOwnerDeleteMessage": true,
			"allowUserEditMessage": true,
			"allowUserDeleteMessage": true,
			"allowUserChat": true,
			"allowGiphy": false
		},
		"SecurityReporting": {
			"reportSecurityConcernsEnabled": true
		}
	}`)

	bag := databag.New("test-tenant", "contoso.com")
	err := parseTeamsJSON(sampleJSON, bag)
	require.NoError(t, err)

	// Verify MeetingPolicy
	require.NotNil(t, bag.TeamsMeetingPolicy)
	assert.False(t, bag.TeamsMeetingPolicy.AllowAnonymousUsersToJoinMeeting)
	assert.Equal(t, "EveryoneInCompanyExcludingGuests", bag.TeamsMeetingPolicy.AutoAdmittedUsers)
	assert.False(t, bag.TeamsMeetingPolicy.AutoRecording)

	// Verify ExternalAccess
	require.NotNil(t, bag.TeamsExternalAccess)
	assert.False(t, bag.TeamsExternalAccess.AllowTeamsConsumer)
	assert.True(t, bag.TeamsExternalAccess.AllowFederatedUsers)
	assert.Equal(t, []string{"partner.com"}, bag.TeamsExternalAccess.AllowedDomains)

	// Verify ClientConfig
	require.NotNil(t, bag.TeamsClientConfig)
	assert.False(t, bag.TeamsClientConfig.AllowDropBox)
	assert.False(t, bag.TeamsClientConfig.AllowGoogleDrive)
	assert.True(t, bag.TeamsClientConfig.AllowEmailIntoChannel)

	// Verify MessagingPolicy
	require.NotNil(t, bag.TeamsMessagingPolicy)
	assert.True(t, bag.TeamsMessagingPolicy.AllowOwnerDeleteMessage)
	assert.False(t, bag.TeamsMessagingPolicy.AllowGiphy)

	// Verify SecurityReporting
	require.NotNil(t, bag.TeamsSecurityReporting)
	assert.True(t, bag.TeamsSecurityReporting.ReportSecurityConcernsEnabled)
}

func TestParseSharePointJSON(t *testing.T) {
	sampleJSON := []byte(`{
		"sharingCapability": "ExternalUserSharingOnly",
		"requireAcceptingAccountMatchInvitedAccount": true,
		"preventExternalUsersFromResharing": true,
		"oneDriveBlockGuestSharing": true,
		"legacyAuthProtocolsEnabled": false,
		"sharingDomainRestrictionMode": "AllowList",
		"sharingAllowedDomainList": ["partner.com", "vendor.com"],
		"sharingBlockedDomainList": [],
		"defaultSharingLinkType": "Internal",
		"isUnmanagedSyncClientForTenantRestricted": true,
		"oneDriveSharingCapability": "ExternalUserSharingOnly",
		"externalUserExpireInDays": 30,
		"emailAttestationReAuthDays": 15,
		"defaultLinkPermission": "View",
		"disallowInfectedFileDownload": true
	}`)

	bag := databag.New("test-tenant", "contoso.com")
	err := parseSharePointJSON(sampleJSON, bag)
	require.NoError(t, err)

	require.NotNil(t, bag.SharePointTenant)
	assert.Equal(t, "ExternalUserSharingOnly", bag.SharePointTenant.SharingCapability)
	assert.True(t, bag.SharePointTenant.RequireAcceptingAccountMatchInvitedAccount)
	assert.True(t, bag.SharePointTenant.PreventExternalUsersFromResharing)
	assert.True(t, bag.SharePointTenant.OneDriveBlockGuestSharing)
	assert.False(t, bag.SharePointTenant.LegacyAuthProtocolsEnabled)
	assert.Equal(t, "AllowList", bag.SharePointTenant.SharingDomainRestrictionMode)
	assert.Equal(t, []string{"partner.com", "vendor.com"}, bag.SharePointTenant.SharingAllowedDomainList)
	assert.Equal(t, "Internal", bag.SharePointTenant.DefaultSharingLinkType)
	assert.True(t, bag.SharePointTenant.IsUnmanagedSyncClientForTenantRestricted)
	assert.Equal(t, 30, bag.SharePointTenant.ExternalUserExpireInDays)
	assert.Equal(t, 15, bag.SharePointTenant.EmailAttestationReAuthDays)
	assert.Equal(t, "View", bag.SharePointTenant.DefaultLinkPermission)
	assert.True(t, bag.SharePointTenant.DisallowInfectedFileDownload)
}

func TestParseExchangeJSON_Empty(t *testing.T) {
	bag := databag.New("test-tenant", "contoso.com")
	err := parseExchangeJSON([]byte(`{}`), bag)
	require.NoError(t, err)
	assert.Nil(t, bag.ExchangeConfig)
	assert.Empty(t, bag.TransportRules)
}

func TestParseTeamsJSON_Empty(t *testing.T) {
	bag := databag.New("test-tenant", "contoso.com")
	err := parseTeamsJSON([]byte(`{}`), bag)
	require.NoError(t, err)
	assert.Nil(t, bag.TeamsMeetingPolicy)
}

func TestParseSharePointJSON_Invalid(t *testing.T) {
	bag := databag.New("test-tenant", "contoso.com")
	err := parseSharePointJSON([]byte(`not json`), bag)
	require.Error(t, err)
	assert.Nil(t, bag.SharePointTenant)
}
