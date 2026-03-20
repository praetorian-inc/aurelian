// Module: azure-recon-misconfigurations
// Provisions intentionally misconfigured Azure resources for testing the
// azure/recon/misconfigurations module, which uses ARG query templates
// plus SDK-based enrichment to detect security misconfigurations.
//
// ==================== TEST CASES ====================
//
// | #  | Resource                     | Template ID                                  | Expected |
// |----|------------------------------|----------------------------------------------|----------|
// | 1  | AKS (local accounts on)      | aks_local_accounts_enabled                   | DETECTED |
// | 2  | Web App (no auth)            | app_service_auth_disabled                    | DETECTED |
// | 3  | Web App (remote debug on)    | app_service_remote_debugging_enabled         | DETECTED |
// | 4  | SQL Server (Azure svc FW)    | databases_allow_azure_services               | DETECTED |
// | 5  | Function App (anon trigger)  | function_app_http_anonymous_access           | DETECTED |
// | 6  | Function App (admin MI)      | function_apps_admin_managed_identity         | DETECTED |
// | 7  | Key Vault (no RBAC)          | key_vault_access_policy_privilege_escalation  | DETECTED |
// | 8  | Kusto (wildcard tenants)     | kusto_wildcard_trusted_tenants               | DETECTED |
// | 9  | NSG (0-65535 port range)     | nsg_unrestricted_port_ranges                 | DETECTED |
// | 10 | Custom Role (*/write)        | overprivileged_custom_roles                  | DETECTED |
// | 11 | Linux VM (priv MI)           | vm_privileged_managed_identity               | DETECTED |
// | 12 | Linux VM (SSH password)      | vm_ssh_password_authentication               | DETECTED |
//
// Note: aks_rbac_disabled is excluded — modern Azure API does not allow
// creating AKS clusters with RBAC disabled.

terraform {
  required_providers {
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

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "db" {
  length  = 24
  special = true
}

locals {
  prefix     = "aur-misconf-${random_string.suffix.result}"
  prefix_san = "aurmc${random_string.suffix.result}"
  location   = "westus2"
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-misconfigurations-testing"
  }
}

#==============================================================================
# RESOURCE GROUP
#==============================================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

#==============================================================================
# NETWORKING (shared by VM, AKS, etc.)
#==============================================================================
resource "azurerm_virtual_network" "test" {
  name                = "${local.prefix}-vnet"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "default" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "aks" {
  name                 = "aks"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.2.0/24"]
}

#==============================================================================
# 1. AKS with local accounts enabled (aks_local_accounts_enabled)
# Default AKS has local_account_disabled = false
#==============================================================================
resource "azurerm_kubernetes_cluster" "local_accounts" {
  name                   = "${local.prefix}-aks"
  resource_group_name    = azurerm_resource_group.test.name
  location               = azurerm_resource_group.test.location
  dns_prefix             = "${local.prefix}-aks"
  local_account_disabled = false

  default_node_pool {
    name           = "default"
    node_count     = 1
    vm_size        = "Standard_B2s"
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  network_profile {
    network_plugin = "azure"
    service_cidr   = "172.16.0.0/16"
    dns_service_ip = "172.16.0.10"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

#==============================================================================
# 2. Web App with auth disabled (app_service_auth_disabled)
# No auth_settings_v2 block → EasyAuth is disabled
#==============================================================================
resource "azurerm_service_plan" "web" {
  name                = "${local.prefix}-plan"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "no_auth" {
  name                = "${local.prefix}-noauth"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.web.id
  site_config {}
  tags = local.tags
}

#==============================================================================
# 3. Web App with remote debugging enabled (app_service_remote_debugging_enabled)
#==============================================================================
resource "azurerm_linux_web_app" "remote_debug" {
  name                = "${local.prefix}-debug"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.web.id

  site_config {
    remote_debugging_enabled = true
    remote_debugging_version = "VS2022"
  }

  tags = local.tags
}

#==============================================================================
# 4. SQL Server with AllowAllAzureIps firewall rule (databases_allow_azure_services)
#==============================================================================
resource "azurerm_mssql_server" "allow_azure" {
  name                         = "${local.prefix}-sql"
  resource_group_name          = azurerm_resource_group.test.name
  location                     = azurerm_resource_group.test.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.db.result
  tags                         = local.tags
}

resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAllWindowsAzureIps"
  server_id        = azurerm_mssql_server.allow_azure.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

#==============================================================================
# 5. Function App with anonymous HTTP trigger (function_app_http_anonymous_access)
# Requires deploying a function with authLevel: anonymous.
# We create the function app and deploy a minimal anonymous function via
# app_setting FUNCTIONS_WORKER_RUNTIME + inline function.json.
#==============================================================================
resource "azurerm_resource_group" "func" {
  name     = "${local.prefix}-func-rg"
  location = local.location
  tags     = local.tags
}

resource "azurerm_storage_account" "func" {
  name                     = "${local.prefix_san}fsa"
  resource_group_name      = azurerm_resource_group.func.name
  location                 = azurerm_resource_group.func.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_service_plan" "func" {
  name                = "${local.prefix}-func-plan"
  resource_group_name = azurerm_resource_group.func.name
  location            = azurerm_resource_group.func.location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.tags
}

# Generate function code with authLevel: anonymous for zip deploy.
resource "local_file" "host_json" {
  filename = "${path.module}/function_code/host.json"
  content = jsonencode({
    version = "2.0"
    extensionBundle = {
      id      = "Microsoft.Azure.Functions.ExtensionBundle"
      version = "[3.*, 4.0.0)"
    }
  })
}

resource "local_file" "function_json" {
  filename = "${path.module}/function_code/HttpTriggerAnon/function.json"
  content = jsonencode({
    bindings = [
      {
        authLevel = "anonymous"
        type      = "httpTrigger"
        direction = "in"
        name      = "req"
        methods   = ["get"]
      },
      {
        type      = "http"
        direction = "out"
        name      = "res"
      }
    ]
  })
}

resource "local_file" "index_js" {
  filename = "${path.module}/function_code/HttpTriggerAnon/index.js"
  content  = "module.exports = async function (context) { context.res = { body: 'ok' }; };"
}

data "archive_file" "anon_function" {
  type        = "zip"
  source_dir  = "${path.module}/function_code"
  output_path = "${path.module}/function_code.zip"
  depends_on  = [local_file.host_json, local_file.function_json, local_file.index_js]
}

resource "azurerm_linux_function_app" "anon_trigger" {
  name                       = "${local.prefix}-anonfunc"
  resource_group_name        = azurerm_resource_group.func.name
  location                   = azurerm_resource_group.func.location
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  zip_deploy_file            = data.archive_file.anon_function.output_path

  site_config {
    application_stack {
      node_version = "18"
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "node"
    WEBSITE_RUN_FROM_PACKAGE = "1"
  }

  tags = local.tags
}

#==============================================================================
# 6. Function App with admin managed identity (function_apps_admin_managed_identity)
# System-assigned MI + Contributor role at subscription scope
#==============================================================================
resource "azurerm_linux_function_app" "admin_mi" {
  name                       = "${local.prefix}-adminfunc"
  resource_group_name        = azurerm_resource_group.func.name
  location                   = azurerm_resource_group.func.location
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      node_version = "18"
    }
  }

  tags = local.tags
}

resource "azurerm_role_assignment" "func_admin_mi" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_function_app.admin_mi.identity[0].principal_id
}

#==============================================================================
# 7. Key Vault without RBAC (key_vault_access_policy_privilege_escalation)
# enableRbacAuthorization = false (uses legacy access policies)
#==============================================================================
resource "azurerm_key_vault" "no_rbac" {
  name                       = "${local.prefix}-kv"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  enable_rbac_authorization  = false
  tags                       = local.tags
}

#==============================================================================
# 8. Kusto cluster with wildcard trusted tenants (kusto_wildcard_trusted_tenants)
# Dev(No SLA) SKU is cheapest (~$0.12/hr)
#==============================================================================
resource "azurerm_kusto_cluster" "wildcard" {
  name                = "${local.prefix_san}kusto"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location

  sku {
    name     = "Dev(No SLA)_Standard_E2a_v4"
    capacity = 1
  }

  trusted_external_tenants = ["*"]
  tags                     = local.tags
}

#==============================================================================
# 9. NSG with unrestricted port range (nsg_unrestricted_port_ranges)
# Inbound Allow rule with destination port range 0-65535
#==============================================================================
resource "azurerm_network_security_group" "wide_open" {
  name                = "${local.prefix}-nsg"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location

  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "0-65535"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }

  tags = local.tags
}

#==============================================================================
# 10. Custom role with privilege escalation permissions (overprivileged_custom_roles)
# Contains Microsoft.Authorization/*/write — enables role self-escalation
#==============================================================================
resource "azurerm_role_definition" "overprivileged" {
  name        = "${local.prefix}-overprivileged-role"
  scope       = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  description = "Test role for misconfiguration detection — DO NOT USE"

  permissions {
    actions = [
      "Microsoft.Authorization/roleAssignments/write",
      "Microsoft.Authorization/roleAssignments/delete",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions = []
  }

  assignable_scopes = [
    "/subscriptions/${data.azurerm_client_config.current.subscription_id}",
  ]
}

#==============================================================================
# 11 + 12. Linux VM with privileged MI + SSH password auth
# (vm_privileged_managed_identity + vm_ssh_password_authentication)
# Two birds, one stone: single VM triggers both templates
#==============================================================================
resource "azurerm_network_interface" "vm" {
  name                = "${local.prefix}-nic"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.default.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = local.tags
}

resource "azurerm_linux_virtual_machine" "priv_mi_password" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  size                            = "Standard_B1ls"
  admin_username                  = "testadmin"
  admin_password                  = random_password.db.result
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.vm.id]

  identity {
    type = "SystemAssigned"
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

resource "azurerm_role_assignment" "vm_priv_mi" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.priv_mi_password.identity[0].principal_id
}

#==============================================================================
# NEGATIVE FIXTURES — correctly configured resources that should NOT be detected
# These prove the enricher drops false positives.
#==============================================================================

# Web App WITH auth enabled — should NOT trigger app_service_auth_disabled
resource "azurerm_linux_web_app" "with_auth" {
  name                = "${local.prefix}-authok"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.web.id

  site_config {}

  auth_settings {
    enabled = true
  }

  tags = local.tags
}

# Key Vault WITH RBAC — should NOT trigger key_vault_access_policy_privilege_escalation
resource "azurerm_key_vault" "with_rbac" {
  name                       = "${local.prefix}-kvok"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  enable_rbac_authorization  = true
  tags                       = local.tags
}
