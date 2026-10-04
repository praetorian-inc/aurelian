#Requires -Modules MicrosoftTeams
param([string]$TenantDomain)

$spFile = Join-Path $env:HOME ".azure" "service_principal_entries.json"
$spEntries = Get-Content $spFile -Raw | ConvertFrom-Json
$sp = $spEntries[0]

$assertionBody = @{
    Grant_Type            = "client_credentials"
    Client_Id             = $sp.client_id
    Client_Assertion      = $sp.client_assertion
    Client_Assertion_Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
}

$graphToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($sp.tenant)/oauth2/v2.0/token" -Method POST -Body ($assertionBody + @{ Scope = "https://graph.microsoft.com/.default" }) |
    Select-Object -ExpandProperty Access_Token

$teamsToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($sp.tenant)/oauth2/v2.0/token" -Method POST -Body ($assertionBody + @{ Scope = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default" }) |
    Select-Object -ExpandProperty Access_Token

Connect-MicrosoftTeams -AccessTokens @("$graphToken", "$teamsToken")

$result = @{
    MeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting, AllowAnonymousUsersToStartMeeting, AllowExternalParticipantGiveRequestControl, AutoAdmittedUsers, AllowCloudRecording, AllowPSTNUsersToBypassLobby, DesignatedPresenterRoleMode, MeetingChatEnabledType, AutoRecording
    ExternalAccess = Get-CsTenantFederationConfiguration | Select-Object AllowTeamsConsumer, AllowTeamsConsumerInbound, AllowFederatedUsers, AllowedDomains, BlockedDomains, AllowPublicUsers
    ClientConfig = Get-CsTeamsClientConfiguration | Select-Object AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte, AllowEmailIntoChannel, RestrictedSenderList
    MessagingPolicy = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowOwnerDeleteMessage, AllowUserEditMessage, AllowUserDeleteMessage, AllowUserChat, AllowGiphy
    SecurityReporting = @{ ReportSecurityConcernsEnabled = (Get-CsTeamsMessagingPolicy -Identity Global).AllowSecurityEndUserReporting }
}

Disconnect-MicrosoftTeams
$result | ConvertTo-Json -Depth 10
