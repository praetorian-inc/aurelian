# Minimum-privilege custom role for the azure/recon/find-secrets module.
#
# The built-in Reader role covers management-plane GET operations (*/read) but
# does not grant the "action" operations, DataActions, or Cosmos DB RBAC that
# find-secrets requires to extract secrets from the following resource types:
#
#   Permission                                                    Resource
#   ─────────────────────────────────────────────────────────────────────────────
#   retrieveBootDiagnosticsData/action                           VM boot diag SAS URLs
#   Microsoft.Web/sites/config/list/action                       Web App / Function App settings + connection strings
#   Microsoft.Web/sites/host/listkeys/action                     Function App host keys
#   Microsoft.Web/sites/slots/config/list/action                 Web App deployment slot settings
#   Microsoft.Web/staticSites/listAppSettings/action             Static Web App settings
#   Microsoft.Storage/storageAccounts/listkeys/action            Storage account shared key (for blob scanning)
#   Microsoft.ApiManagement/service/namedValues/listValue/action APIM named values
#   DataAction: Microsoft.AppConfiguration/configurationStores/*/read  App Configuration data plane
#
# Cosmos DB data-plane access is controlled by a separate RBAC system and must
# be granted independently per account — see azurerm_cosmosdb_sql_role_assignment
# below. The built-in role ID 00000000-0000-0000-0000-000000000001 is
# "Cosmos DB Built-in Data Reader".
#
# Usage:
#   1. Deploy this file alongside the find-secrets test fixture (or standalone).
#   2. Assign both Reader and this custom role to the principal running aurelian.
#   3. For each Cosmos DB account to be scanned, deploy the
#      azurerm_cosmosdb_sql_role_assignment resource (see below).

data "azurerm_client_config" "rbac_current" {}
data "azurerm_subscription" "rbac_current" {}

# ─── Custom role ─────────────────────────────────────────────────────────────

resource "azurerm_role_definition" "aurelian_find_secrets" {
  name        = "aurelian-find-secrets"
  scope       = data.azurerm_subscription.rbac_current.id
  description = "Minimum permissions beyond Reader for the aurelian azure/recon/find-secrets module."

  permissions {
    actions = [
      # VM boot diagnostics: SAS URLs for serial console / screenshot storage blobs.
      "Microsoft.Compute/virtualMachines/retrieveBootDiagnosticsData/action",

      # Web App / Function App: app settings, connection strings, and slot settings.
      # These are POST list operations, not covered by */read.
      "Microsoft.Web/sites/config/list/action",
      "Microsoft.Web/sites/slots/config/list/action",

      # Function App host keys (master key + function keys).
      "Microsoft.Web/sites/host/listkeys/action",

      # Static Web App: application settings via list action.
      "Microsoft.Web/staticSites/listAppSettings/action",

      # Storage accounts: shared key required for data-plane blob access.
      # The extractor authenticates to the storage data plane using the account key.
      "Microsoft.Storage/storageAccounts/listkeys/action",

      # API Management: named value secret retrieval.
      "Microsoft.ApiManagement/service/namedValues/listValue/action",
    ]

    data_actions = [
      # App Configuration: data-plane read for key-values.
      # Reader's */read covers the management plane only; data plane requires this DataAction.
      "Microsoft.AppConfiguration/configurationStores/*/read",
    ]
  }

  assignable_scopes = [
    data.azurerm_subscription.rbac_current.id,
  ]
}

# ─── Role assignments ─────────────────────────────────────────────────────────
# Assign both Reader (built-in) and this custom role to the principal.
# Replace var.principal_id with the object ID of the service principal / managed identity.

variable "principal_id" {
  description = "Object ID of the principal (service principal or managed identity) running aurelian find-secrets."
  type        = string
}

resource "azurerm_role_assignment" "aurelian_reader" {
  scope                = data.azurerm_subscription.rbac_current.id
  role_definition_name = "Reader"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "aurelian_find_secrets" {
  scope              = data.azurerm_subscription.rbac_current.id
  role_definition_id = azurerm_role_definition.aurelian_find_secrets.role_definition_resource_id
  principal_id       = var.principal_id
}

# ─── Cosmos DB RBAC ──────────────────────────────────────────────────────────
# Cosmos DB uses its own authorization system separate from Azure RBAC.
# Grant "Cosmos DB Built-in Data Reader" per account to enable document scanning.
#
# Uncomment and repeat for each Cosmos DB account to be scanned:
#
# resource "azurerm_cosmosdb_sql_role_assignment" "aurelian_find_secrets" {
#   resource_group_name = "<resource-group>"
#   account_name        = "<cosmos-account-name>"
#   role_definition_id  = "${data.azurerm_subscription.rbac_current.id}/resourceGroups/<resource-group>/providers/Microsoft.DocumentDB/databaseAccounts/<cosmos-account-name>/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
#   principal_id        = var.principal_id
#   scope               = "/subscriptions/${data.azurerm_client_config.rbac_current.subscription_id}/resourceGroups/<resource-group>/providers/Microsoft.DocumentDB/databaseAccounts/<cosmos-account-name>"
# }
