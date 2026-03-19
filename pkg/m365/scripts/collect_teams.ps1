#Requires -Modules MicrosoftTeams
param([string]$TenantDomain)

Connect-MicrosoftTeams

$result = @{
    MeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting, AllowAnonymousUsersToStartMeeting, AllowExternalParticipantGiveRequestControl, AutoAdmittedUsers, AllowCloudRecording, AllowPSTNUsersToBypassLobby, DesignatedPresenterRoleMode, MeetingChatEnabledType, AutoRecording
    ExternalAccess = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer, AllowTeamsConsumerInbound, AllowFederatedUsers, AllowedDomains, BlockedDomains, AllowPublicUsers
    ClientConfig = Get-CsTeamsClientConfiguration | Select-Object AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte, AllowEmailIntoChannel, RestrictedSenderList
    MessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowOwnerDeleteMessage, AllowUserEditMessage, AllowUserDeleteMessage, AllowUserChat, AllowGiphy
    SecurityReporting = @{ ReportSecurityConcernsEnabled = (Get-CsTeamsMessagingPolicy -Identity Global).AllowSecurityEndUserReporting }
}

Disconnect-MicrosoftTeams
$result | ConvertTo-Json -Depth 10
