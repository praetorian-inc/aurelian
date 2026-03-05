// Module: azure-recon-find-secrets
// Scans Azure resources for hardcoded secrets using Titus.
//
// This fixture provisions resources with embedded secrets so the module
// can discover them. Each resource contains a known fake secret string.
//
// | #  | Resource                     | Secret Location          | Expected Result |
// |----|------------------------------|--------------------------|-----------------|
// | 1  | VM with userData             | base64-encoded userData  | DETECTED        |
// | 2  | Web App with app settings    | app settings value       | DETECTED        |
// | 3  | Automation Account variable  | variable value           | DETECTED        |
// | 4  | Storage Account blob         | blob content             | DETECTED        |

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
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {}
}

provider "azurerm" {
  features {
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
  prefix     = "aur-fs-${random_string.suffix.result}"
  prefix_san = "aurfs${random_string.suffix.result}"
  location   = var.location
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-find-secrets-testing"
  }
  # A fake AWS-style secret key that Titus will detect
  fake_secret = "AKIAIOSFODNN7EXAMPLE"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus2"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = ""
}

#==============================================================================
# Resource Group
#==============================================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

#==============================================================================
# 1. Virtual Machine with userData containing a secret
#==============================================================================
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
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.test.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "test" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  size                            = "Standard_B1ls"
  admin_username                  = "testadmin"
  disable_password_authentication = true
  tags                            = local.tags

  admin_ssh_key {
    username   = "testadmin"
    public_key = tls_private_key.test.public_key_openssh
  }

  network_interface_ids = [azurerm_network_interface.test.id]

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

  user_data = base64encode("#!/bin/bash\n# Config\nAWS_SECRET_ACCESS_KEY=${local.fake_secret}\nexport AWS_SECRET_ACCESS_KEY\n")
}

resource "tls_private_key" "test" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

#==============================================================================
# 2. Web App with app settings containing a secret
#==============================================================================
resource "azurerm_service_plan" "test" {
  name                = "${local.prefix}-asp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "test" {
  name                = "${local.prefix}-webapp"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.test.id
  tags                = local.tags

  site_config {}

  app_settings = {
    "SECRET_API_KEY" = local.fake_secret
  }
}

#==============================================================================
# 3. Automation Account with a variable containing a secret
#==============================================================================
resource "azurerm_automation_account" "test" {
  name                = "${local.prefix}-aa"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku_name            = "Basic"
  tags                = local.tags
}

resource "azurerm_automation_variable_string" "test" {
  name                    = "secret_credential"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = local.fake_secret
}

#==============================================================================
# 4. Storage Account with a blob containing a secret
#==============================================================================
resource "azurerm_storage_account" "test" {
  name                     = "${local.prefix_san}sa"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_storage_container" "test" {
  name                  = "secrets-test"
  storage_account_name  = azurerm_storage_account.test.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "test" {
  name                   = "config.env"
  storage_account_name   = azurerm_storage_account.test.name
  storage_container_name = azurerm_storage_container.test.name
  type                   = "Block"
  source_content         = "# Configuration\nAWS_SECRET_ACCESS_KEY=${local.fake_secret}\nDB_HOST=localhost\n"
}

#==============================================================================
# Outputs
#==============================================================================
output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "vm_id" {
  value = azurerm_linux_virtual_machine.test.id
}

output "webapp_id" {
  value = azurerm_linux_web_app.test.id
}

output "automation_account_id" {
  value = azurerm_automation_account.test.id
}

output "storage_account_id" {
  value = azurerm_storage_account.test.id
}
