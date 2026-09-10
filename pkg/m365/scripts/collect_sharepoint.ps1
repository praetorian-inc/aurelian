#Requires -Modules Microsoft.Online.SharePoint.PowerShell
param([string]$AdminUrl)

Connect-SPOService -Url $AdminUrl

$tenant = Get-SPOTenant
$result = @{
    SharingCapability = $tenant.SharingCapability.ToString()
    RequireAcceptingAccountMatchInvitedAccount = $tenant.RequireAcceptingAccountMatchInvitedAccount
    PreventExternalUsersFromResharing = $tenant.PreventExternalUsersFromResharing
    OneDriveBlockGuestSharing = $tenant.OneDriveSharingCapability -eq 'Disabled'
    LegacyAuthProtocolsEnabled = $tenant.LegacyAuthProtocolsEnabled
    SharingDomainRestrictionMode = $tenant.SharingDomainRestrictionMode.ToString()
    SharingAllowedDomainList = @($tenant.SharingAllowedDomainList -split ',')
    SharingBlockedDomainList = @($tenant.SharingBlockedDomainList -split ',')
    DefaultSharingLinkType = $tenant.DefaultSharingLinkType.ToString()
    IsUnmanagedSyncClientForTenantRestricted = $tenant.IsUnmanagedSyncClientForTenantRestricted
    OneDriveSharingCapability = $tenant.OneDriveSharingCapability.ToString()
    ExternalUserExpireInDays = $tenant.ExternalUserExpireInDays
    EmailAttestationReAuthDays = $tenant.EmailAttestationReAuthDays
    DefaultLinkPermission = $tenant.DefaultLinkPermission.ToString()
    DisallowInfectedFileDownload = $tenant.DisallowInfectedFileDownload
}

Disconnect-SPOService
$result | ConvertTo-Json -Depth 10
