// Module: azure-recon-list-all
// Enumerates all Azure resources in a subscription using Azure Resource Graph (ARG).
// The module sends a KQL query to the ARG API and paginates through results.
//
// Detection: Queries the ARG API with "Resources | project id, name, type, location,
// resourceGroup, tags, properties" and returns all rows as AzureResource structs.
//
// ==================== TEST CASES ====================
//
// This is a recon/enumeration module. All resources are "true positives" --
// the module must discover every resource provisioned in the subscription.
//
// | #  | Resource Name                | Type        | Azure Resource Type                              | Expected Result |
// |----|------------------------------|-------------|--------------------------------------------------|-----------------|
// | 1  | ${prefix}-rg                 | ResourceGrp | Microsoft.Resources/resourceGroups                | DISCOVERED      |
// | 2  | ${prefix}-vnet               | VNet        | Microsoft.Network/virtualNetworks                 | DISCOVERED      |
// | 3  | ${prefix}-subnet             | Subnet      | (child of VNet, may not appear in ARG)            | DISCOVERED*     |
// | 4  | ${prefix}-nsg                | NSG         | Microsoft.Network/networkSecurityGroups            | DISCOVERED      |
// | 5  | ${prefix_san}sa              | Storage     | Microsoft.Storage/storageAccounts                  | DISCOVERED      |
// | 6  | ${prefix}-kv                 | KeyVault    | Microsoft.KeyVault/vaults                          | DISCOVERED      |
// | 7  | ${prefix}-law                | LogAnalytic | Microsoft.OperationalInsights/workspaces            | DISCOVERED      |
// | 8  | ${prefix_san}acr             | ACR         | Microsoft.ContainerRegistry/registries              | DISCOVERED      |
// | 9  | ${prefix}-adf                | DataFactory | Microsoft.DataFactory/factories                     | DISCOVERED      |
// | 10 | ${prefix}-egt                | EventGrid   | Microsoft.EventGrid/topics                          | DISCOVERED      |
// | 11 | ${prefix}-sbns               | ServiceBus  | Microsoft.ServiceBus/namespaces                     | DISCOVERED      |
// | 12 | ${prefix}-asp                | AppSvcPlan  | Microsoft.Web/serverFarms                           | DISCOVERED      |
// | 13 | ${prefix}-webapp             | WebApp      | Microsoft.Web/sites                                 | DISCOVERED      |
// | 14 | ${prefix_san}fsa             | Storage     | Microsoft.Storage/storageAccounts                   | DISCOVERED      |
// | 15 | ${prefix}-func-asp           | AppSvcPlan  | Microsoft.Web/serverFarms                           | DISCOVERED      |
// | 16 | ${prefix}-func               | FuncApp     | Microsoft.Web/sites                                 | DISCOVERED      |
// | 17 | ${prefix}-aa                 | Automation  | Microsoft.Automation/automationAccounts             | DISCOVERED      |
// | 18 | ${prefix}-sql                | SQL Server  | Microsoft.Sql/servers                               | DISCOVERED      |
// | 19 | ${prefix}-nic                | NIC         | Microsoft.Network/networkInterfaces                 | DISCOVERED      |
// | 20 | ${prefix}-vm                 | VM          | Microsoft.Compute/virtualMachines                   | DISCOVERED      |
//
// * Subnets are child resources and may not appear as top-level ARG results.
//   The all_resource_ids output excludes the subnet for this reason.

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

  # Local state by default. The Azure fixture passes -backend-config="path=..."
  # at init time to store state in a stable temp directory.
  backend "local" {}
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
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

locals {
  prefix     = "aurelian-itest-${random_string.suffix.result}"
  prefix_san = "aurelianitest${random_string.suffix.result}" # alphanumeric only, for storage accounts and ACR
  location   = var.location
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-list-all-testing"
  }
}

#==============================================================================
# RESOURCE 01: Resource Group
# All other resources are created inside this resource group.
#==============================================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

#==============================================================================
# RESOURCE 02: Virtual Network
#==============================================================================
resource "azurerm_virtual_network" "test" {
  name                = "${local.prefix}-vnet"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

#==============================================================================
# RESOURCE 03: Subnet (child resource -- may not appear in top-level ARG)
#==============================================================================
resource "azurerm_subnet" "test" {
  name                 = "${local.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

#==============================================================================
# RESOURCE 04: Network Security Group
#==============================================================================
resource "azurerm_network_security_group" "test" {
  name                = "${local.prefix}-nsg"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

#==============================================================================
# RESOURCE 05: Storage Account
#==============================================================================
resource "azurerm_storage_account" "test" {
  name                     = "${local.prefix_san}sa"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

#==============================================================================
# RESOURCE 06: Key Vault
#==============================================================================
resource "azurerm_key_vault" "test" {
  name                       = "${local.prefix}-kv"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = local.tags
}

#==============================================================================
# RESOURCE 07: Log Analytics Workspace
#==============================================================================
resource "azurerm_log_analytics_workspace" "test" {
  name                = "${local.prefix}-law"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

#==============================================================================
# RESOURCE 08: Container Registry (Basic SKU -- cheapest)
#==============================================================================
resource "azurerm_container_registry" "test" {
  name                = "${local.prefix_san}acr"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

#==============================================================================
# RESOURCE 09: Data Factory
#==============================================================================
resource "azurerm_data_factory" "test" {
  name                = "${local.prefix}-adf"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

#==============================================================================
# RESOURCE 10: Event Grid Topic
#==============================================================================
resource "azurerm_eventgrid_topic" "test" {
  name                = "${local.prefix}-egt"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

#==============================================================================
# RESOURCE 11: Service Bus Namespace (Standard SKU)
#==============================================================================
resource "azurerm_servicebus_namespace" "test" {
  name                = "${local.prefix}-sbns"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "Standard"
  tags                = local.tags
}

#==============================================================================
# RESOURCE 12: App Service Plan (Linux B1 -- cheapest non-free)
#==============================================================================
resource "azurerm_service_plan" "test" {
  name                = "${local.prefix}-asp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

#==============================================================================
# RESOURCE 13: Linux Web App
#==============================================================================
resource "azurerm_linux_web_app" "test" {
  name                = "${local.prefix}-webapp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.test.id

  site_config {}
  tags = local.tags
}

#==============================================================================
# RESOURCE 14: Storage Account for Function App
#==============================================================================
resource "azurerm_storage_account" "funcsa" {
  name                     = "${local.prefix_san}fsa"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

#==============================================================================
# RESOURCE 15: Function App Service Plan (Consumption Y1)
#==============================================================================
resource "azurerm_service_plan" "func" {
  name                = "${local.prefix}-func-asp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.tags
}

#==============================================================================
# RESOURCE 16: Linux Function App
#==============================================================================
resource "azurerm_linux_function_app" "test" {
  name                       = "${local.prefix}-func"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.funcsa.name
  storage_account_access_key = azurerm_storage_account.funcsa.primary_access_key

  site_config {}
  tags = local.tags
}

#==============================================================================
# RESOURCE 17: Automation Account (Basic SKU)
#==============================================================================
resource "azurerm_automation_account" "test" {
  name                = "${local.prefix}-aa"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku_name            = "Basic"
  tags                = local.tags
}

#==============================================================================
# RESOURCE 18: SQL Server (logical server, no database)
#==============================================================================
resource "azurerm_mssql_server" "test" {
  name                         = "${local.prefix}-sql"
  resource_group_name          = azurerm_resource_group.test.name
  location                     = azurerm_resource_group.test.location
  version                      = "12.0"
  administrator_login          = "aurelianadmin"
  administrator_login_password = "P@ssw0rd${random_string.suffix.result}!"
  tags                         = local.tags
}

#==============================================================================
# RESOURCE 19: Network Interface (required for VM)
#==============================================================================
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

#==============================================================================
# RESOURCE 20: Linux Virtual Machine (Standard_B1ls -- smallest/cheapest)
#==============================================================================
resource "azurerm_linux_virtual_machine" "test" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  size                            = "Standard_B1ls"
  admin_username                  = "aurelianadmin"
  admin_password                  = "P@ssw0rd${random_string.suffix.result}!"
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.test.id]

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
