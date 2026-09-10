#Requires -Modules ExchangeOnlineManagement
param([string]$TenantDomain)

# Connect using managed identity / device code from env
Connect-ExchangeOnline -ShowBanner:$false

$result = @{
    OrgConfig = Get-OrganizationConfig | Select-Object AuditDisabled, OAuth2ClientProfileEnabled, SmtpClientAuthenticationDisabled, MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold, DirectSendRestricted
    TransportRules = @(Get-TransportRule | Select-Object Name, State, Mode, SenderDomainIs, RedirectMessageTo, RouteMessageOutboundConnector, SetHeaderName, SetHeaderValue, SetSCL)
    MailboxAuditConfigs = @(Get-Mailbox -ResultSize Unlimited | Select-Object Identity, AuditEnabled, AuditLogAgeLimit, AuditBypassEnabled, AuditAdmin, AuditDelegate, AuditOwner)
    RoleAssignmentPolicies = @(Get-RoleAssignmentPolicy | Select-Object Name, IsDefault, AssignedRoles)
    MailboxPolicies = @(Get-OwaMailboxPolicy | Select-Object Name, ThirdPartyFileProvidersEnabled, AdditionalStorageProvidersAvailable)
    SharedMailboxes = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Select-Object Identity, AccountDisabled, @{N='SignInEnabled';E={-not $_.AccountDisabled}})
    ExternalInOutlook = Get-ExternalInOutlook | Select-Object Enabled
}

Disconnect-ExchangeOnline -Confirm:$false
$result | ConvertTo-Json -Depth 10
