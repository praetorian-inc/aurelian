// Module: azure-recon-iam-graph
// Provisions deterministic Entra ID + ARM fixtures for Azure IAM graph integration tests.
// Every entity and relationship is explicit so the Go test can assert exact counts.
//
// ==================== TEST FIXTURE SUMMARY ====================
//
// ENTRA ID ENTITIES:
//   Users:              12 (global_admin, priv_role_admin, app_admin, user_admin,
//                           auth_admin, helpdesk_admin, password_admin, regular_user,
//                           priv_auth_admin, groups_admin, conditional_access_admin,
//                           exchange_admin)
//   Groups:             2 (privileged_group, regular_group)
//   Applications:       2 (privileged_app, regular_app)
//   Service Principals: 2 (from the 2 apps above)
//
// ENTRA ID RELATIONSHIPS:
//   Directory Role Assignments:  12 (one per admin user + 1 for privileged group)
//   Group Memberships:           3 (regular_user→regular_group, auth_admin→privileged_group,
//                                   privileged_group→regular_group [nested])
//   Ownership:                   3 (app_admin→privileged_app, app_admin→privileged_group,
//                                   user_admin→regular_app SP)
//   App Role Assignments:        1 (privileged_app SP gets RoleManagement.ReadWrite.Directory
//                                   on Microsoft Graph)
//
// ARM ENTITIES:
//   Resource Group:          1
//   User-Assigned MI:        1
//   Linux VM (system MI):    1 (with system-assigned identity + user-assigned MI attached)
//   NIC:                     1 (required by VM)
//   VNet + Subnet:           1+1 (required by NIC)
//
// RBAC ASSIGNMENTS:
//   Owner:              1 (global_admin on subscription)
//   User Access Admin:  1 (priv_role_admin on resource group)
//
// PIM INFRASTRUCTURE:
//   PIM Reader App:     1 (app registration with RoleManagement.Read.Directory +
//                          Directory.Read.All + Application.Read.All)
//   PIM Eligible:       1 (regular_user eligible for Global Administrator)
//
// EXPECTED ENRICHMENT RESULTS (after all 38 YAML queries):
//   CAN_ESCALATE edges:      See outputs.tf for exact per-method counts
//   Enrichment markers:      _isGlobalAdmin, _hasPrivilegedRole, _canEscalate, etc.

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {}
}

provider "azuread" {}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

data "azuread_client_config" "current" {}
data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  prefix     = "aurelian-iam-${random_string.suffix.result}"
  prefix_san = "aurelianiam${random_string.suffix.result}"
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-iam-graph-testing"
  }

  # Well-known Entra ID built-in role template IDs
  role_global_admin             = "62e90394-69f5-4237-9190-012177145e10"
  role_priv_role_admin          = "e8611ab8-c189-46e8-94e1-60213ab1f814"
  role_app_admin                = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
  role_user_admin               = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  role_auth_admin               = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
  role_helpdesk_admin           = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
  role_password_admin           = "966707d0-3269-4727-9be2-8c3a10f19b9d"
  role_priv_auth_admin          = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
  role_groups_admin             = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
  role_conditional_access_admin = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
  role_exchange_admin           = "29232cdf-9323-42fd-ade2-1d097af3e4de"

  # Microsoft Graph well-known app ID and service principal
  msgraph_app_id = "00000003-0000-0000-c000-000000000000"

  # Common password for test users
  user_password = "AurelianTest!${random_string.suffix.result}#2024"
}

# =============================================================================
# Microsoft Graph Service Principal (data source — already exists in every tenant)
# =============================================================================
data "azuread_service_principal" "msgraph" {
  client_id = local.msgraph_app_id
}

# =============================================================================
# USERS (8 total)
# =============================================================================
resource "azuread_user" "global_admin" {
  user_principal_name = "${local.prefix}-globaladmin@${var.domain}"
  display_name        = "${local.prefix} Global Admin"
  password            = local.user_password
}

resource "azuread_user" "priv_role_admin" {
  user_principal_name = "${local.prefix}-privroleadmin@${var.domain}"
  display_name        = "${local.prefix} Priv Role Admin"
  password            = local.user_password
}

resource "azuread_user" "app_admin" {
  user_principal_name = "${local.prefix}-appadmin@${var.domain}"
  display_name        = "${local.prefix} App Admin"
  password            = local.user_password
}

resource "azuread_user" "user_admin" {
  user_principal_name = "${local.prefix}-useradmin@${var.domain}"
  display_name        = "${local.prefix} User Admin"
  password            = local.user_password
}

resource "azuread_user" "auth_admin" {
  user_principal_name = "${local.prefix}-authadmin@${var.domain}"
  display_name        = "${local.prefix} Auth Admin"
  password            = local.user_password
}

resource "azuread_user" "helpdesk_admin" {
  user_principal_name = "${local.prefix}-helpdeskadmin@${var.domain}"
  display_name        = "${local.prefix} Helpdesk Admin"
  password            = local.user_password
}

resource "azuread_user" "password_admin" {
  user_principal_name = "${local.prefix}-passwordadmin@${var.domain}"
  display_name        = "${local.prefix} Password Admin"
  password            = local.user_password
}

resource "azuread_user" "priv_auth_admin" {
  user_principal_name = "${local.prefix}-privauthadmin@${var.domain}"
  display_name        = "${local.prefix} Priv Auth Admin"
  password            = local.user_password
}

resource "azuread_user" "groups_admin" {
  user_principal_name = "${local.prefix}-groupsadmin@${var.domain}"
  display_name        = "${local.prefix} Groups Admin"
  password            = local.user_password
}

resource "azuread_user" "conditional_access_admin" {
  user_principal_name = "${local.prefix}-condaccessadmin@${var.domain}"
  display_name        = "${local.prefix} Conditional Access Admin"
  password            = local.user_password
}

resource "azuread_user" "exchange_admin" {
  user_principal_name = "${local.prefix}-exchangeadmin@${var.domain}"
  display_name        = "${local.prefix} Exchange Admin"
  password            = local.user_password
}

resource "azuread_user" "regular" {
  user_principal_name = "${local.prefix}-regular@${var.domain}"
  display_name        = "${local.prefix} Regular User"
  password            = local.user_password
}

# =============================================================================
# DIRECTORY ROLE ASSIGNMENTS (7 total — one per admin user)
# =============================================================================
resource "azuread_directory_role_assignment" "global_admin" {
  role_id             = local.role_global_admin
  principal_object_id = azuread_user.global_admin.object_id
}

resource "azuread_directory_role_assignment" "priv_role_admin" {
  role_id             = local.role_priv_role_admin
  principal_object_id = azuread_user.priv_role_admin.object_id
}

resource "azuread_directory_role_assignment" "app_admin" {
  role_id             = local.role_app_admin
  principal_object_id = azuread_user.app_admin.object_id
}

resource "azuread_directory_role_assignment" "user_admin" {
  role_id             = local.role_user_admin
  principal_object_id = azuread_user.user_admin.object_id
}

resource "azuread_directory_role_assignment" "auth_admin" {
  role_id             = local.role_auth_admin
  principal_object_id = azuread_user.auth_admin.object_id
}

resource "azuread_directory_role_assignment" "helpdesk_admin" {
  role_id             = local.role_helpdesk_admin
  principal_object_id = azuread_user.helpdesk_admin.object_id
}

resource "azuread_directory_role_assignment" "password_admin" {
  role_id             = local.role_password_admin
  principal_object_id = azuread_user.password_admin.object_id
}

resource "azuread_directory_role_assignment" "priv_auth_admin" {
  role_id             = local.role_priv_auth_admin
  principal_object_id = azuread_user.priv_auth_admin.object_id
}

resource "azuread_directory_role_assignment" "groups_admin" {
  role_id             = local.role_groups_admin
  principal_object_id = azuread_user.groups_admin.object_id
}

resource "azuread_directory_role_assignment" "conditional_access_admin" {
  role_id             = local.role_conditional_access_admin
  principal_object_id = azuread_user.conditional_access_admin.object_id
}

resource "azuread_directory_role_assignment" "exchange_admin" {
  role_id             = local.role_exchange_admin
  principal_object_id = azuread_user.exchange_admin.object_id
}

# =============================================================================
# GROUPS (2 total)
# =============================================================================
resource "azuread_group" "privileged" {
  display_name       = "${local.prefix}-privileged-group"
  security_enabled   = true
  assignable_to_role = true
  owners             = [azuread_user.app_admin.object_id, data.azuread_client_config.current.object_id]
}

# Assign a directory role to the privileged group (triggers can_escalate_group_owner)
resource "azuread_directory_role_assignment" "privileged_group_user_admin" {
  role_id             = local.role_user_admin
  principal_object_id = azuread_group.privileged.object_id
}

resource "azuread_group" "regular" {
  display_name     = "${local.prefix}-regular-group"
  security_enabled = true
}

# =============================================================================
# GROUP MEMBERSHIPS (3 total)
# regular_user → regular_group
# auth_admin → privileged_group
# privileged_group → regular_group (nested group — tests group_nesting_paths)
# =============================================================================
resource "azuread_group_member" "regular_user_in_regular_group" {
  group_object_id  = azuread_group.regular.object_id
  member_object_id = azuread_user.regular.object_id
}

resource "azuread_group_member" "auth_admin_in_privileged_group" {
  group_object_id  = azuread_group.privileged.object_id
  member_object_id = azuread_user.auth_admin.object_id
}

resource "azuread_group_member" "privileged_group_in_regular_group" {
  group_object_id  = azuread_group.regular.object_id
  member_object_id = azuread_group.privileged.object_id
}

# =============================================================================
# APPLICATIONS + SERVICE PRINCIPALS (2 apps, 2 SPs)
# =============================================================================
resource "azuread_application" "privileged" {
  display_name = "${local.prefix}-privileged-app"

  required_resource_access {
    resource_app_id = local.msgraph_app_id

    resource_access {
      # RoleManagement.ReadWrite.Directory
      id   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "privileged" {
  client_id = azuread_application.privileged.client_id
}

# Grant admin consent for the app role assignment
resource "azuread_app_role_assignment" "privileged_graph_role_mgmt" {
  app_role_id         = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement.ReadWrite.Directory
  principal_object_id = azuread_service_principal.privileged.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azuread_application" "regular" {
  display_name = "${local.prefix}-regular-app"
}

# Client secret on privileged_app so that stale_credentials.yaml enrichment fires.
# The iam-pull collector stores credentials on Application nodes; the enrichment
# query matches WHERE app.credentials IS NOT NULL.
resource "azuread_application_password" "privileged" {
  application_id = azuread_application.privileged.id
  display_name   = "integration-test-stale-cred"
  end_date       = "2027-12-31T00:00:00Z"
}

resource "azuread_service_principal" "regular" {
  client_id = azuread_application.regular.client_id
  owners    = [azuread_user.user_admin.object_id, data.azuread_client_config.current.object_id]
}

# =============================================================================
# OWNERSHIP RELATIONSHIPS (2 total)
# app_admin OWNS privileged_app (triggers can_escalate_app_owner_secret)
# user_admin OWNS regular_app SP (triggers can_escalate_sp_owner_secret)
# =============================================================================
resource "azuread_application_owner" "app_admin_owns_privileged_app" {
  application_id  = azuread_application.privileged.id
  owner_object_id = azuread_user.app_admin.object_id
}

# SP ownership for user_admin → regular SP is set via azuread_service_principal.regular owners attribute

# =============================================================================
# ARM RESOURCES — Resource Group, VNet, Subnet, NIC, VM (with MI), User-Assigned MI
# =============================================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = var.location
  tags     = local.tags
}

resource "azurerm_user_assigned_identity" "test" {
  name                = "${local.prefix}-mi"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

resource "azurerm_virtual_network" "test" {
  name                = "${local.prefix}-vnet"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "test" {
  name                 = "${local.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_interface" "test" {
  name                = "${local.prefix}-nic"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.test.id
    private_ip_address_allocation = "Dynamic"
  }
  tags = local.tags
}

# VM with BOTH system-assigned and user-assigned managed identities
resource "azurerm_linux_virtual_machine" "test" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  size                            = "Standard_B1ls"
  admin_username                  = "aurelianadmin"
  admin_password                  = "P@ssw0rd${random_string.suffix.result}!"
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.test.id]

  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.test.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  tags = local.tags
}

# =============================================================================
# RBAC ASSIGNMENTS (2 total)
# global_admin gets Owner on subscription
# priv_role_admin gets User Access Administrator on resource group
# =============================================================================
resource "azurerm_role_assignment" "owner_on_sub" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Owner"
  principal_id         = azuread_user.global_admin.object_id
}

resource "azurerm_role_assignment" "uaa_on_rg" {
  scope                = azurerm_resource_group.test.id
  role_definition_name = "User Access Administrator"
  principal_id         = azuread_user.priv_role_admin.object_id
}

# =============================================================================
# PIM APP REGISTRATION (for PIM API access in integration tests)
# The Azure CLI first-party app cannot consent to RoleManagement.Read.Directory,
# so we create a dedicated app registration with the necessary Graph permissions.
# =============================================================================
resource "azuread_application" "pim_reader" {
  display_name = "${local.prefix}-pim-reader"

  required_resource_access {
    resource_app_id = local.msgraph_app_id

    # RoleManagement.Read.Directory (application)
    resource_access {
      id   = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
      type = "Role"
    }

    # Directory.Read.All (application) — needed for user/group/SP enumeration
    resource_access {
      id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
      type = "Role"
    }

    # Application.Read.All (application) — needed for app enumeration
    resource_access {
      id   = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "pim_reader" {
  client_id = azuread_application.pim_reader.client_id
}

# Grant admin consent for PIM reader permissions
resource "azuread_app_role_assignment" "pim_reader_role_mgmt_read" {
  app_role_id         = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c" # RoleManagement.Read.Directory
  principal_object_id = azuread_service_principal.pim_reader.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azuread_app_role_assignment" "pim_reader_directory_read" {
  app_role_id         = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All
  principal_object_id = azuread_service_principal.pim_reader.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azuread_app_role_assignment" "pim_reader_app_read" {
  app_role_id         = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" # Application.Read.All
  principal_object_id = azuread_service_principal.pim_reader.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# Client secret for the PIM reader app
resource "azuread_application_password" "pim_reader" {
  application_id = azuread_application.pim_reader.id
  display_name   = "integration-test"
  end_date       = "2027-12-31T00:00:00Z"
}

# =============================================================================
# PIM ELIGIBLE ROLE ASSIGNMENTS
# Creates eligible (not active) assignments that the PIM enrichment query detects.
# Requires Azure AD Premium P2.
# =============================================================================
resource "azuread_directory_role_eligibility_schedule_request" "regular_user_eligible_global_admin" {
  role_definition_id = "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
  principal_id       = azuread_user.regular.object_id
  directory_scope_id = "/"
  justification      = "Aurelian integration test - PIM eligible escalation"
}
