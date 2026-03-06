// Module: azure-recon-find-secrets
// Provisions Azure resources containing embedded secrets for integration testing
// of the azure/recon/find-secrets module.
//
// ==================== TEST CASES ====================
//
// | #  | Resource                | Secret Location                      | Expected Result |
// |----|-------------------------|--------------------------------------|-----------------|
// | 1  | Linux VM                | user_data (base64-encoded script)    | DETECTED        |
// | 2  | Linux Web App           | app setting                          | DETECTED        |
// | 3  | Automation Account      | automation variable                  | DETECTED        |
// | 4  | Storage Account         | blob containing secret               | DETECTED        |

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
  prefix     = "aur-sec-${random_string.suffix.result}"
  prefix_san = "aursec${random_string.suffix.result}" # alphanumeric only for storage accounts
  location   = var.location
  tags = {
    ManagedBy = "terraform"
    Purpose   = "aurelian-find-secrets-testing"
  }

  # Intentionally fake credentials used only for secret-detection testing.
  fake_aws_key    = "AKIAIOSFODNN7EXAMPLE"
  fake_aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ============================================================
# Resource Group
# ============================================================
resource "azurerm_resource_group" "test" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

# ============================================================
# 1. Linux VM — secret in user data
# ============================================================
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

resource "azurerm_linux_virtual_machine" "test" {
  name                            = "${local.prefix}-vm"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  size                            = "Standard_B1ls"
  admin_username                  = "aurelianadmin"
  admin_password                  = "P@ssw0rd${random_string.suffix.result}!"
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.test.id]

  user_data = base64encode(<<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="${local.fake_aws_key}"
    export AWS_SECRET_ACCESS_KEY="${local.fake_aws_secret}"
    echo "configured"
  EOF
  )

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

# ============================================================
# 2. Linux Web App — secret in app settings
# ============================================================
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

  site_config {}

  app_settings = {
    "AWS_ACCESS_KEY_ID"     = local.fake_aws_key
    "AWS_SECRET_ACCESS_KEY" = local.fake_aws_secret
  }

  tags = local.tags
}

# ============================================================
# 3. Automation Account — secret in a variable
# ============================================================
resource "azurerm_automation_account" "test" {
  name                = "${local.prefix}-aa"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku_name            = "Basic"
  tags                = local.tags
}

resource "azurerm_automation_variable_string" "secret" {
  name                    = "secret_key"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
}

# ============================================================
# 4. Storage Account — blob containing a secret
# ============================================================
resource "azurerm_storage_account" "test" {
  name                     = "${local.prefix_san}sa"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
}

resource "azurerm_storage_container" "test" {
  name                  = "secrets"
  storage_account_name  = azurerm_storage_account.test.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "secret" {
  name                   = "config.env"
  storage_account_name   = azurerm_storage_account.test.name
  storage_container_name = azurerm_storage_container.test.name
  type                   = "Block"
  source_content         = "AWS_ACCESS_KEY_ID=${local.fake_aws_key}\nAWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}\n"
}
