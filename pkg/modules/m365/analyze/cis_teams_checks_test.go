package analyze

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// ---------------------------------------------------------------------------
// 8.1.1 - checkTeamsExternalFileShareRestricted
// ---------------------------------------------------------------------------

func TestCheckTeamsExternalFileShareRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowDropBox:    false,
			AllowBox:        false,
			AllowGoogleDrive: false,
			AllowShareFile:  false,
			AllowEgnyte:     false,
		},
	}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsExternalFileShareRestricted_Fail_DropBox(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowDropBox:    true,
			AllowBox:        false,
			AllowGoogleDrive: false,
			AllowShareFile:  false,
			AllowEgnyte:     false,
		},
	}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when DropBox is allowed")
	}
}

func TestCheckTeamsExternalFileShareRestricted_Fail_Multiple(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowDropBox:    true,
			AllowBox:        true,
			AllowGoogleDrive: true,
			AllowShareFile:  false,
			AllowEgnyte:     false,
		},
	}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with multiple providers enabled")
	}
}

func TestCheckTeamsExternalFileShareRestricted_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil teams client config")
	}
}

// ---------------------------------------------------------------------------
// 8.1.2 - checkTeamsEmailToChannelDisabled
// ---------------------------------------------------------------------------

func TestCheckTeamsEmailToChannelDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowEmailIntoChannel: false,
		},
	}

	result, err := checkTeamsEmailToChannelDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsEmailToChannelDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowEmailIntoChannel: true,
		},
	}

	result, err := checkTeamsEmailToChannelDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when email to channel is allowed")
	}
}

func TestCheckTeamsEmailToChannelDisabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsEmailToChannelDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil config")
	}
}

// ---------------------------------------------------------------------------
// 8.2.1 - checkTeamsExternalDomainAccessDisabled
// ---------------------------------------------------------------------------

func TestCheckTeamsExternalDomainAccessDisabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowFederatedUsers: false,
		},
	}

	result, err := checkTeamsExternalDomainAccessDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsExternalDomainAccessDisabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowFederatedUsers: true,
		},
	}

	result, err := checkTeamsExternalDomainAccessDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when federated users are allowed")
	}
}

func TestCheckTeamsExternalDomainAccessDisabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsExternalDomainAccessDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil config")
	}
}

// ---------------------------------------------------------------------------
// 8.2.2 - checkTeamsNoUnmanagedUsers
// ---------------------------------------------------------------------------

func TestCheckTeamsNoUnmanagedUsers_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowTeamsConsumer: false,
		},
	}

	result, err := checkTeamsNoUnmanagedUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsNoUnmanagedUsers_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowTeamsConsumer: true,
		},
	}

	result, err := checkTeamsNoUnmanagedUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when Teams consumer access is allowed")
	}
}

func TestCheckTeamsNoUnmanagedUsers_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsNoUnmanagedUsers(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil config")
	}
}

// ---------------------------------------------------------------------------
// 8.2.3 - checkTeamsExternalUsersCannotStartConversation
// ---------------------------------------------------------------------------

func TestCheckTeamsExternalUsersCannotStartConversation_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowTeamsConsumerInbound: false,
		},
	}

	result, err := checkTeamsExternalUsersCannotStartConversation(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsExternalUsersCannotStartConversation_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowTeamsConsumerInbound: true,
		},
	}

	result, err := checkTeamsExternalUsersCannotStartConversation(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when consumer inbound is allowed")
	}
}

func TestCheckTeamsExternalUsersCannotStartConversation_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsExternalUsersCannotStartConversation(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil config")
	}
}

// ---------------------------------------------------------------------------
// 8.5.1 - checkTeamsAnonymousCannotJoin
// ---------------------------------------------------------------------------

func TestCheckTeamsAnonymousCannotJoin_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowAnonymousUsersToJoinMeeting: false,
		},
	}

	result, err := checkTeamsAnonymousCannotJoin(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsAnonymousCannotJoin_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowAnonymousUsersToJoinMeeting: true,
		},
	}

	result, err := checkTeamsAnonymousCannotJoin(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when anonymous users can join")
	}
}

func TestCheckTeamsAnonymousCannotJoin_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsAnonymousCannotJoin(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.2 - checkTeamsAnonymousCannotStart
// ---------------------------------------------------------------------------

func TestCheckTeamsAnonymousCannotStart_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowAnonymousUsersToStartMeeting: false,
		},
	}

	result, err := checkTeamsAnonymousCannotStart(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsAnonymousCannotStart_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowAnonymousUsersToStartMeeting: true,
		},
	}

	result, err := checkTeamsAnonymousCannotStart(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when anonymous users can start meetings")
	}
}

func TestCheckTeamsAnonymousCannotStart_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsAnonymousCannotStart(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.3 - checkTeamsOnlyOrgUsersBypassLobby
// ---------------------------------------------------------------------------

func TestCheckTeamsOnlyOrgUsersBypassLobby_Pass_ExcludingGuests(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "EveryoneInCompanyExcludingGuests",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsOnlyOrgUsersBypassLobby_Pass_EveryoneInCompany(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "EveryoneInCompany",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsOnlyOrgUsersBypassLobby_Fail_Everyone(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "Everyone",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when Everyone can bypass lobby")
	}
}

func TestCheckTeamsOnlyOrgUsersBypassLobby_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.4 - checkTeamsDialInCannotBypassLobby
// ---------------------------------------------------------------------------

func TestCheckTeamsDialInCannotBypassLobby_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowPSTNUsersToBypassLobby: false,
		},
	}

	result, err := checkTeamsDialInCannotBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsDialInCannotBypassLobby_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowPSTNUsersToBypassLobby: true,
		},
	}

	result, err := checkTeamsDialInCannotBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when PSTN users can bypass lobby")
	}
}

func TestCheckTeamsDialInCannotBypassLobby_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsDialInCannotBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.5 - checkTeamsAnonymousBlockedFromChat
// ---------------------------------------------------------------------------

func TestCheckTeamsAnonymousBlockedFromChat_Pass_ExceptAnonymous(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "EnabledExceptAnonymous",
		},
	}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsAnonymousBlockedFromChat_Pass_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "Disabled",
		},
	}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsAnonymousBlockedFromChat_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "Enabled",
		},
	}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when chat is enabled for everyone")
	}
}

func TestCheckTeamsAnonymousBlockedFromChat_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.6 - checkTeamsOnlyOrganizersPresent
// ---------------------------------------------------------------------------

func TestCheckTeamsOnlyOrganizersPresent_Pass_OrganizerOnly(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			DesignatedPresenterRoleMode: "OrganizerOnlyUserOverride",
		},
	}

	result, err := checkTeamsOnlyOrganizersPresent(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsOnlyOrganizersPresent_Fail_Everyone(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			DesignatedPresenterRoleMode: "EveryoneUserOverride",
		},
	}

	result, err := checkTeamsOnlyOrganizersPresent(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when everyone can present")
	}
}

func TestCheckTeamsOnlyOrganizersPresent_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsOnlyOrganizersPresent(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.7 - checkTeamsExternalCannotControl
// ---------------------------------------------------------------------------

func TestCheckTeamsExternalCannotControl_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowExternalParticipantGiveRequestControl: false,
		},
	}

	result, err := checkTeamsExternalCannotControl(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsExternalCannotControl_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AllowExternalParticipantGiveRequestControl: true,
		},
	}

	result, err := checkTeamsExternalCannotControl(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when external participants can control")
	}
}

func TestCheckTeamsExternalCannotControl_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsExternalCannotControl(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.8 - checkTeamsMeetingChatRestricted
// ---------------------------------------------------------------------------

func TestCheckTeamsMeetingChatRestricted_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "EnabledExceptAnonymous",
		},
	}

	result, err := checkTeamsMeetingChatRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsMeetingChatRestricted_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "Enabled",
		},
	}

	result, err := checkTeamsMeetingChatRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when meeting chat is fully enabled")
	}
}

func TestCheckTeamsMeetingChatRestricted_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsMeetingChatRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.5.9 - checkTeamsRecordingOffByDefault
// ---------------------------------------------------------------------------

func TestCheckTeamsRecordingOffByDefault_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoRecording: false,
		},
	}

	result, err := checkTeamsRecordingOffByDefault(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsRecordingOffByDefault_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoRecording: true,
		},
	}

	result, err := checkTeamsRecordingOffByDefault(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when auto-recording is enabled")
	}
}

func TestCheckTeamsRecordingOffByDefault_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsRecordingOffByDefault(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil meeting policy")
	}
}

// ---------------------------------------------------------------------------
// 8.6.1 - checkTeamsSecurityReportingEnabled
// ---------------------------------------------------------------------------

func TestCheckTeamsSecurityReportingEnabled_Pass(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsSecurityReporting: &databag.TeamsSecurityReporting{
			ReportSecurityConcernsEnabled: true,
		},
	}

	result, err := checkTeamsSecurityReportingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass, got: %s", result.Message)
	}
}

func TestCheckTeamsSecurityReportingEnabled_Fail(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsSecurityReporting: &databag.TeamsSecurityReporting{
			ReportSecurityConcernsEnabled: false,
		},
	}

	result, err := checkTeamsSecurityReportingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when security reporting is disabled")
	}
}

func TestCheckTeamsSecurityReportingEnabled_Fail_Nil(t *testing.T) {
	bag := &databag.M365DataBag{TenantID: "test-tenant"}

	result, err := checkTeamsSecurityReportingEnabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with nil security reporting config")
	}
}

// ---------------------------------------------------------------------------
// Edge-case and negative tests
// ---------------------------------------------------------------------------

func TestCheckTeamsExternalFileShare_SingleProvider(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowDropBox:     false,
			AllowBox:         false,
			AllowGoogleDrive: true,
			AllowShareFile:   false,
			AllowEgnyte:      false,
		},
	}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when only AllowGoogleDrive is true")
	}
}

func TestCheckTeamsExternalFileShare_AllProvidersTrue(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsClientConfig: &databag.TeamsClientConfig{
			AllowDropBox:     true,
			AllowBox:         true,
			AllowGoogleDrive: true,
			AllowShareFile:   true,
			AllowEgnyte:      true,
		},
	}

	result, err := checkTeamsExternalFileShareRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when all 5 providers are enabled")
	}
}

func TestCheckTeamsExternalDomains_EmptyAllowedDomains(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsExternalAccess: &databag.TeamsExternalAccessPolicy{
			AllowFederatedUsers: true,
			AllowedDomains:      []string{},
		},
	}

	result, err := checkTeamsExternalDomainAccessDisabled(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail when AllowFederatedUsers=true even with empty AllowedDomains")
	}
}

func TestCheckTeamsLobbyBypass_OrganizerOnly(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "OrganizerOnly",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with OrganizerOnly (not an accepted value)")
	}
}

func TestCheckTeamsLobbyBypass_EmptyString(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty AutoAdmittedUsers string")
	}
}

func TestCheckTeamsLobbyBypass_UnknownValue(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			AutoAdmittedUsers: "SomethingNew",
		},
	}

	result, err := checkTeamsOnlyOrgUsersBypassLobby(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with unknown AutoAdmittedUsers value")
	}
}

func TestCheckTeamsMeetingChat_EmptyType(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "",
		},
	}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty MeetingChatEnabledType")
	}
}

func TestCheckTeamsMeetingChat_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "Disabled",
		},
	}

	result, err := checkTeamsAnonymousBlockedFromChat(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with Disabled chat type, got: %s", result.Message)
	}
}

func TestCheckTeamsPresenter_EmptyMode(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			DesignatedPresenterRoleMode: "",
		},
	}

	result, err := checkTeamsOnlyOrganizersPresent(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Passed {
		t.Fatal("expected check to fail with empty DesignatedPresenterRoleMode")
	}
}

func TestCheckTeamsMeetingChatRestricted_Disabled(t *testing.T) {
	bag := &databag.M365DataBag{
		TenantID: "test-tenant",
		TeamsMeetingPolicy: &databag.TeamsMeetingPolicy{
			MeetingChatEnabledType: "Disabled",
		},
	}

	result, err := checkTeamsMeetingChatRestricted(context.Background(), bag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected check to pass with Disabled chat type, got: %s", result.Message)
	}
}
