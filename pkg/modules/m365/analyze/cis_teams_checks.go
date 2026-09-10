package analyze

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/m365/checks"
	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func init() {
	checks.Register("8.1.1", checkTeamsExternalFileShareRestricted)
	checks.Register("8.1.2", checkTeamsEmailToChannelDisabled)
	checks.Register("8.2.1", checkTeamsExternalDomainAccessDisabled)
	checks.Register("8.2.2", checkTeamsNoUnmanagedUsers)
	checks.Register("8.2.3", checkTeamsExternalUsersCannotStartConversation)
	checks.Register("8.5.1", checkTeamsAnonymousCannotJoin)
	checks.Register("8.5.2", checkTeamsAnonymousCannotStart)
	checks.Register("8.5.3", checkTeamsOnlyOrgUsersBypassLobby)
	checks.Register("8.5.4", checkTeamsDialInCannotBypassLobby)
	checks.Register("8.5.5", checkTeamsAnonymousBlockedFromChat)
	checks.Register("8.5.6", checkTeamsOnlyOrganizersPresent)
	checks.Register("8.5.7", checkTeamsExternalCannotControl)
	checks.Register("8.5.8", checkTeamsMeetingChatRestricted)
	checks.Register("8.5.9", checkTeamsRecordingOffByDefault)
	checks.Register("8.6.1", checkTeamsSecurityReportingEnabled)
	checks.Register("8.2.4", checkTeamsSkypeDisabled)
}

// 8.1.1: Ensure external file sharing in Teams is restricted to approved cloud storage providers
func checkTeamsExternalFileShareRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsClientConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams client configuration not available",
		}, nil
	}

	cfg := bag.TeamsClientConfig
	var enabledProviders []string
	if cfg.AllowDropBox {
		enabledProviders = append(enabledProviders, "DropBox")
	}
	if cfg.AllowBox {
		enabledProviders = append(enabledProviders, "Box")
	}
	if cfg.AllowGoogleDrive {
		enabledProviders = append(enabledProviders, "GoogleDrive")
	}
	if cfg.AllowShareFile {
		enabledProviders = append(enabledProviders, "ShareFile")
	}
	if cfg.AllowEgnyte {
		enabledProviders = append(enabledProviders, "Egnyte")
	}

	if len(enabledProviders) == 0 {
		return &checks.CheckResult{
			Passed:  true,
			Message: "All third-party cloud storage providers are disabled in Teams",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    fmt.Sprintf("External file sharing is enabled for %d provider(s)", len(enabledProviders)),
		Evidence: map[string]any{
			"enabled_providers": enabledProviders,
		},
	}, nil
}

// 8.1.2: Ensure users can't send emails to a channel email address
func checkTeamsEmailToChannelDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsClientConfig == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams client configuration not available",
		}, nil
	}

	if !bag.TeamsClientConfig.AllowEmailIntoChannel {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Email sending to channel email addresses is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Users can send emails to channel email addresses",
		Evidence: map[string]any{
			"allowEmailIntoChannel": bag.TeamsClientConfig.AllowEmailIntoChannel,
		},
	}, nil
}

// 8.2.1: Ensure external domain access is disabled for Teams
func checkTeamsExternalDomainAccessDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsExternalAccess == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams external access policy not available",
		}, nil
	}

	if !bag.TeamsExternalAccess.AllowFederatedUsers {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External domain access is disabled for Teams",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External domain access is enabled for Teams",
		Evidence: map[string]any{
			"allowFederatedUsers": bag.TeamsExternalAccess.AllowFederatedUsers,
			"allowedDomains":      bag.TeamsExternalAccess.AllowedDomains,
		},
	}, nil
}

// 8.2.2: Ensure communication with unmanaged Teams users is disabled
func checkTeamsNoUnmanagedUsers(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsExternalAccess == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams external access policy not available",
		}, nil
	}

	if !bag.TeamsExternalAccess.AllowTeamsConsumer {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Communication with unmanaged Teams users is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Communication with unmanaged Teams users is allowed",
		Evidence: map[string]any{
			"allowTeamsConsumer": bag.TeamsExternalAccess.AllowTeamsConsumer,
		},
	}, nil
}

// 8.2.3: Ensure external users cannot initiate conversations
func checkTeamsExternalUsersCannotStartConversation(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsExternalAccess == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams external access policy not available",
		}, nil
	}

	if !bag.TeamsExternalAccess.AllowTeamsConsumerInbound {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External users cannot start conversations with org users",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External users can start conversations with org users",
		Evidence: map[string]any{
			"allowTeamsConsumerInbound": bag.TeamsExternalAccess.AllowTeamsConsumerInbound,
		},
	}, nil
}

// 8.5.1: Ensure anonymous users can't join meetings
func checkTeamsAnonymousCannotJoin(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	if !bag.TeamsMeetingPolicy.AllowAnonymousUsersToJoinMeeting {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Anonymous users cannot join meetings",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Anonymous users are allowed to join meetings",
		Evidence: map[string]any{
			"allowAnonymousUsersToJoinMeeting": bag.TeamsMeetingPolicy.AllowAnonymousUsersToJoinMeeting,
		},
	}, nil
}

// 8.5.2: Ensure anonymous users can't start meetings
func checkTeamsAnonymousCannotStart(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	if !bag.TeamsMeetingPolicy.AllowAnonymousUsersToStartMeeting {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Anonymous users cannot start meetings",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Anonymous users are allowed to start meetings",
		Evidence: map[string]any{
			"allowAnonymousUsersToStartMeeting": bag.TeamsMeetingPolicy.AllowAnonymousUsersToStartMeeting,
		},
	}, nil
}

// 8.5.3: Ensure only people in my org can bypass the lobby
func checkTeamsOnlyOrgUsersBypassLobby(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	// AutoAdmittedUsers should be "EveryoneInCompanyExcludingGuests" or "EveryoneInCompany"
	// for this check to pass; "Everyone" would allow external users to bypass lobby.
	admitted := strings.ToLower(bag.TeamsMeetingPolicy.AutoAdmittedUsers)
	if admitted == "everyoneincompanyexcludingguests" || admitted == "everyoneincompany" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Only organization users can bypass the lobby",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Users outside the organization can bypass the lobby",
		Evidence: map[string]any{
			"autoAdmittedUsers": bag.TeamsMeetingPolicy.AutoAdmittedUsers,
		},
	}, nil
}

// 8.5.4: Ensure dial-in users cannot bypass the lobby
func checkTeamsDialInCannotBypassLobby(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	if !bag.TeamsMeetingPolicy.AllowPSTNUsersToBypassLobby {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Dial-in (PSTN) users cannot bypass the lobby",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Dial-in (PSTN) users can bypass the lobby",
		Evidence: map[string]any{
			"allowPSTNUsersToBypassLobby": bag.TeamsMeetingPolicy.AllowPSTNUsersToBypassLobby,
		},
	}, nil
}

// 8.5.5: Ensure meeting chat is restricted for anonymous users
func checkTeamsAnonymousBlockedFromChat(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	// MeetingChatEnabledType should be "EnabledExceptAnonymous" or "Disabled"
	chatType := strings.ToLower(bag.TeamsMeetingPolicy.MeetingChatEnabledType)
	if chatType == "enabledexceptanonymous" || chatType == "disabled" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Anonymous users are blocked from meeting chat",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Anonymous users can participate in meeting chat",
		Evidence: map[string]any{
			"meetingChatEnabledType": bag.TeamsMeetingPolicy.MeetingChatEnabledType,
		},
	}, nil
}

// 8.5.6: Ensure only organizers and co-organizers can present
func checkTeamsOnlyOrganizersPresent(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	// DesignatedPresenterRoleMode should be "OrganizerOnlyUserOverride" or similar restrictive value
	mode := strings.ToLower(bag.TeamsMeetingPolicy.DesignatedPresenterRoleMode)
	if mode == "organizeronlyuseroverride" || mode == "organizeronly" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Only organizers and co-organizers can present in meetings",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Meeting presentation is not restricted to organizers/co-organizers",
		Evidence: map[string]any{
			"designatedPresenterRoleMode": bag.TeamsMeetingPolicy.DesignatedPresenterRoleMode,
		},
	}, nil
}

// 8.5.7: Ensure external participants can't give or request control
func checkTeamsExternalCannotControl(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	if !bag.TeamsMeetingPolicy.AllowExternalParticipantGiveRequestControl {
		return &checks.CheckResult{
			Passed:  true,
			Message: "External participants cannot give or request control",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "External participants can give or request control in meetings",
		Evidence: map[string]any{
			"allowExternalParticipantGiveRequestControl": bag.TeamsMeetingPolicy.AllowExternalParticipantGiveRequestControl,
		},
	}, nil
}

// 8.5.8: Ensure meeting chat is disabled for untrusted organizations
func checkTeamsMeetingChatRestricted(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	// MeetingChatEnabledType should not be "Enabled" (unrestricted)
	chatType := strings.ToLower(bag.TeamsMeetingPolicy.MeetingChatEnabledType)
	if chatType != "enabled" {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Meeting chat is restricted for untrusted organizations",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Meeting chat is enabled for all participants including untrusted organizations",
		Evidence: map[string]any{
			"meetingChatEnabledType": bag.TeamsMeetingPolicy.MeetingChatEnabledType,
		},
	}, nil
}

// 8.5.9: Ensure meeting recording is turned off by default
func checkTeamsRecordingOffByDefault(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsMeetingPolicy == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams meeting policy not available",
		}, nil
	}

	if !bag.TeamsMeetingPolicy.AutoRecording {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Automatic meeting recording is disabled by default",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Automatic meeting recording is enabled by default",
		Evidence: map[string]any{
			"autoRecording": bag.TeamsMeetingPolicy.AutoRecording,
		},
	}, nil
}

// 8.6.1: Ensure users can report security concerns in Teams
func checkTeamsSecurityReportingEnabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsSecurityReporting == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams security reporting configuration not available",
		}, nil
	}

	if bag.TeamsSecurityReporting.ReportSecurityConcernsEnabled {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Users can report security concerns in Teams messaging",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Security concern reporting is not enabled in Teams messaging",
		Evidence: map[string]any{
			"reportSecurityConcernsEnabled": bag.TeamsSecurityReporting.ReportSecurityConcernsEnabled,
		},
	}, nil
}

// 8.2.4: Ensure communication with Skype users is disabled
func checkTeamsSkypeDisabled(_ context.Context, bag *databag.M365DataBag) (*checks.CheckResult, error) {
	if bag.TeamsExternalAccess == nil {
		return &checks.CheckResult{
			Passed:     false,
			ResourceID: bag.TenantID,
			Message:    "Teams external access policy not available",
		}, nil
	}

	if !bag.TeamsExternalAccess.AllowPublicUsers {
		return &checks.CheckResult{
			Passed:  true,
			Message: "Communication with Skype users is disabled",
		}, nil
	}

	return &checks.CheckResult{
		Passed:     false,
		ResourceID: bag.TenantID,
		Message:    "Communication with Skype users is allowed",
		Evidence: map[string]any{
			"allowPublicUsers": bag.TeamsExternalAccess.AllowPublicUsers,
		},
	}, nil
}
