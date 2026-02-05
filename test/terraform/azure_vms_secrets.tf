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
}

variable "subscription_id" {
  description = "The subscription ID to deploy the resources in"
  type        = string
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# Random strings for unique names
resource "random_uuid" "test" {}

resource "random_string" "storage_account" {
  length  = 8
  special = false
  upper   = false
  numeric = true
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources-${random_uuid.test.result}"
  location = "East US"
}

resource "azurerm_virtual_network" "example" {
  name                = "example-network-${random_uuid.test.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "example" {
  name                 = "internal-${random_uuid.test.result}"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic-${random_uuid.test.result}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal-${random_uuid.test.result}"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_storage_account" "boot_diagnostics" {
  name                     = "bootdiag${random_string.storage_account.result}"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Boot diagnostics secrets in tags
  tags = {
    connection_string = "DefaultEndpointsProtocol=https;AccountName=examplebootdiag;AccountKey=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;EndpointSuffix=core.windows.net"
    diag_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWFnbm9zdGljcyIsInNlcnZpY2UiOiJib290ZGlhZyIsInBlcm1pc3Npb25zIjoicmVhZHdyaXRlIn0.dBh5azRxJg6RVtLKqPlevWEiFYqQLrE7wL5dFvD8Gpc"
  }
}

resource "azurerm_linux_virtual_machine" "example" {
  name                  = "example-vm-${random_uuid.test.result}"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_interface.example.id]
  size                  = "Standard_DS1_v2"

  # Custom data (userdata) with secrets
  custom_data = base64encode(<<CUSTOM_DATA
#!/bin/bash
echo "AWS_ACCESS_KEY_ID=AKIA4YFAKL6RDQMPL123" >> /etc/environment
echo "AWS_SECRET_ACCESS_KEY=p2rPn0JfhgFkVCKzBXtYUVF3RJp45tWsafS1z8AQ" >> /etc/environment
echo "GOOGLE_APPLICATION_CREDENTIALS='{\"type\":\"service_account\",\"project_id\":\"my-project\",\"private_key_id\":\"abc123\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9QFi6JzJrKaX+\\nabc123def456...\\n-----END PRIVATE KEY-----\\n\"}'" >> /root/gcp-creds.json
# Azure AD JWT token for API access
echo "AZURE_API_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8iLCJpYXQiOjE2NDE0ODIxNjAsIm5iZiI6MTY0MTQ4MjE2MCwiZXhwIjoxNjQxNDg2MDYwLCJhaW8iOiJFMkpnWU5qZFhYbDVzamRzZnNmU0QyOTJweTY5ODR2Mkp6ZnhxNDZYWEp2WjhOYzBSNDBVIiwiYXBwaWQiOiIxMjM0NTY3OC05YWJjLWRlZjAtMTIzNC01Njc4OTBhYmNkZWYiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8iLCJvaWQiOiI5ODc2NTQzMi0xYWJjLTIzZGUtNDVmZy03ODlhYmNkZWYwMTIiLCJyaCI6IjAuQVRjQUdrTS1lLVVYNzAyWHBIRmh4Qk9mSVFrQUFBQUFBQUFBd0FBQUFBQUFBQUE4LiIsInN1YiI6Ijk4NzY1NDMyLTFhYmMtMjNkZS00NWZnLTc4OWFiY2RlZjAxMiIsInRpZCI6IjEyMzQ1Njc4LTkwYWItY2RlZi0xMjM0LTU2Nzg5MGFiY2RlZiIsInV0aSI6IjEyMzQ1Ni1hYmNkZWYtNzg5MC0xMjM0LTU2Nzg5MCIsInZlciI6IjEuMCJ9.HKFbgX2zvdN3Kf5qhkBfX2F1M2XG3kFQQXYUC-6G8KE9khzT6jB1oFOB-2iqM0yB7N4I7HQz9yD9NqXMm9b0O8Fj5qU1h0TCqfW5X9Z3wQ8J3V8U5K3H2K6X1Y9J5Q" >> /etc/environment
CUSTOM_DATA
  )

  os_disk {
    name                 = "myosdisk1-${random_uuid.test.result}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  computer_name  = "win${substr(random_uuid.test.result, 0, 4)}"
  admin_username = "adminuser"
  admin_password = "P@ssw0rd1234!"

  disable_password_authentication = false

  # Boot diagnostics configuration
  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.boot_diagnostics.primary_blob_endpoint
  }
}

# Custom Script Extension with secrets
resource "azurerm_virtual_machine_extension" "custom_script" {
  name                 = "custom-script-${random_uuid.test.result}"
  virtual_machine_id   = azurerm_linux_virtual_machine.example.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.0"

  settings = jsonencode({
    "commandToExecute": "sh -c 'echo \"MANAGEMENT_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrZXkiOiJzZWNyZXQiLCJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.8HtZGF9xWb8dj3qCqMoH_2dWBFBX7A8lKp20Jk1i0Uw\" > /tmp/tokens.txt'"
  })
}

# Additional NIC for Windows VM
resource "azurerm_network_interface" "windows" {
  name                = "windows-nic-${random_uuid.test.result}"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal-win-${random_uuid.test.result}"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Windows VM with secrets in custom data and extensions
resource "azurerm_windows_virtual_machine" "example" {
  name                  = "windows-vm-${random_uuid.test.result}"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_interface.windows.id]
  size                  = "Standard_D2s_v3"

  # Custom data (userdata) with secrets
  custom_data = base64encode(<<CUSTOM_DATA
<powershell>
$env:STRIPE_SECRET_KEY = "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"
$env:GITHUB_TOKEN = "ghp_kHj2P4LzWRtNXQz6vYj8wC9LKqM3nVpBxD1s"
$env:AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=windowsdiag;AccountKey=jKH8kYrQp2NmWvX5tZc3bL9nBdF6gM4qS7hJ2xK8;EndpointSuffix=core.windows.net"
</powershell>
CUSTOM_DATA
  )

  os_disk {
    name                 = "windows-osdisk-${random_uuid.test.result}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }

  computer_name  = "win${substr(random_uuid.test.result, 0, 4)}"
  admin_username = "winadmin"
  admin_password = "P@ssw0rd9876!"

  # Boot diagnostics
  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.boot_diagnostics.primary_blob_endpoint
  }
}

# Windows Custom Script Extension with secrets
resource "azurerm_virtual_machine_extension" "windows_custom_script" {
  name                 = "windows-script-${random_uuid.test.result}"
  virtual_machine_id   = azurerm_windows_virtual_machine.example.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  settings = jsonencode({
    "commandToExecute" : "powershell.exe -Command \"[System.Environment]::SetEnvironmentVariable('SENDGRID_API_KEY', 'SG.1234567890.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 'Machine'); [System.Environment]::SetEnvironmentVariable('JWT_SECRET', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZWNyZXQiOiJ3aW5kb3dzX3NlcnZpY2VfYWNjb3VudCJ9.7QR9wThKXd1CP1KqkzIZ4X1Rq8dzN5-ZVutAM3T8nko', 'Machine')\""
  })
}
