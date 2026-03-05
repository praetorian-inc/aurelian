terraform {
  backend "s3" {}
}

locals {
  random_suffix = random_string.suffix.result
  name_prefix   = "test-vm-userdata"
  location      = "Central US"
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Resource group for VM userdata testing
resource "azurerm_resource_group" "test" {
  name     = "${local.name_prefix}-${local.random_suffix}"
  location = local.location

  tags = {
    Purpose = "nebula-vm-userdata-secrets-testing"
    Module  = "vm-userdata-secrets"
  }
}

# Virtual Network and Subnet
resource "azurerm_virtual_network" "test" {
  name                = "${local.name_prefix}-vnet-${local.random_suffix}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
}

resource "azurerm_subnet" "test" {
  name                 = "${local.name_prefix}-subnet-${local.random_suffix}"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "test" {
  name                = "${local.name_prefix}-nic-${local.random_suffix}"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  ip_configuration {
    name                          = "testconfiguration"
    subnet_id                     = azurerm_subnet.test.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Network interface for second VM
resource "azurerm_network_interface" "test_custom" {
  name                = "${local.name_prefix}-nic-custom-${local.random_suffix}"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  ip_configuration {
    name                          = "testconfiguration2"
    subnet_id                     = azurerm_subnet.test.id
    private_ip_address_allocation = "Dynamic"
  }
}

# VM with secrets in user data
resource "azurerm_linux_virtual_machine" "test" {
  name                = "${local.name_prefix}-vm-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"

  # User data containing various types of secrets for comprehensive testing
  user_data = base64encode(<<-EOF
    #!/bin/bash
    
    # Database credentials
    export DB_PASSWORD="vm-userdata-secret-password-${local.random_suffix}"
    export DB_CONNECTION="Server=testserver.database.windows.net;Database=testdb;User ID=testuser;Password=vm-secret-${local.random_suffix};"
    
    # API Keys and tokens
    export API_KEY="AKIA1234567890ABCDEF"
    export SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    export BEARER_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    # Cloud service keys
    export AZURE_CLIENT_SECRET="azure-client-secret-${local.random_suffix}"
    export AWS_SECRET_ACCESS_KEY="aws-secret-access-key-${local.random_suffix}"
    export GCP_SERVICE_ACCOUNT_KEY='{"type": "service_account", "project_id": "test-project", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VGmBq7R5V6...\\n-----END PRIVATE KEY-----\\n"}'
    
    # Application secrets
    export ENCRYPTION_KEY="encryption-key-${local.random_suffix}"
    export OAUTH_CLIENT_SECRET="oauth-secret-${local.random_suffix}"
    export WEBHOOK_SECRET="webhook-secret-${local.random_suffix}"
    
    # Third-party service credentials
    export SLACK_TOKEN="xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
    export GITHUB_TOKEN="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"
    export SENDGRID_API_KEY="SG.1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyz"
    
    echo "Starting application with embedded secrets..."
    
    # Connection strings in comments (should still be detected)
    # mongodb://username:password@host:port/database
    # redis://user:redis-password-${local.random_suffix}@localhost:6379
    
    # Private keys in configuration
    cat > /tmp/app.conf << 'EOL'
[database]
host = localhost
password = config-file-password-${local.random_suffix}

[ssl]
private_key = -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
KLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ
-----END RSA PRIVATE KEY-----
EOL
    
    echo "VM userdata setup complete"
  EOF
  )

  disable_password_authentication = true

  network_interface_ids = [
    azurerm_network_interface.test.id,
  ]

  admin_ssh_key {
    username   = "adminuser"
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeOVs+8rWFQ27iCotsopt5Dk7BprUy9jYyZTrTHjK4hiEtArZi4dTnN57iqfk7KGHcKcsNcdgB+z8laAymFhkNGc2aMkuvauelt7hKGULMxUw2OJz/P7HQ+btJJhcmIXwJ9JnhoPhmUbAMBTvQ2BYsbdKB0euQUpJJ4NCSZyimfCSODXwUDCXcSCPMuR2uUOPlR1K4sZwrG+1kByzNOH6fayUUp9AZlaiNxM96p9j6MjKkLbhipLyl8zG33wsEKCOjAYEauze5ipIGewH8Xn7gXoU4WsJcQ220dRGHDhHjmYEIXPeBCm7nJSVSr97vMMNdKgWzIeDvERhWJSfUxTBN test@example.com"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "latest"
  }

  tags = {
    Purpose     = "nebula-vm-userdata-secrets-testing"
    Module      = "vm-userdata-secrets"
    SecretTypes = "database-passwords,api-keys,connection-strings,private-keys"
  }
}

# Additional VM with custom data for testing
resource "azurerm_linux_virtual_machine" "test_custom" {
  name                = "${local.name_prefix}-custom-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    # Custom data with different secret patterns
    export CUSTOM_SECRET="custom-data-secret-${local.random_suffix}"
    export JWT_SECRET="jwt-secret-key-${local.random_suffix}"
    
    # Database URLs
    export DATABASE_URL="postgresql://user:custom-db-password-${local.random_suffix}@localhost:5432/mydb"
    export REDIS_URL="redis://:custom-redis-password-${local.random_suffix}@localhost:6379"
    
    echo "Custom data VM setup complete"
  EOF
  )

  disable_password_authentication = true

  network_interface_ids = [
    azurerm_network_interface.test_custom.id,
  ]

  depends_on = [azurerm_linux_virtual_machine.test]

  admin_ssh_key {
    username   = "adminuser"
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeOVs+8rWFQ27iCotsopt5Dk7BprUy9jYyZTrTHjK4hiEtArZi4dTnN57iqfk7KGHcKcsNcdgB+z8laAymFhkNGc2aMkuvauelt7hKGULMxUw2OJz/P7HQ+btJJhcmIXwJ9JnhoPhmUbAMBTvQ2BYsbdKB0euQUpJJ4NCSZyimfCSODXwUDCXcSCPMuR2uUOPlR1K4sZwrG+1kByzNOH6fayUUp9AZlaiNxM96p9j6MjKkLbhipLyl8zG33wsEKCOjAYEauze5ipIGewH8Xn7gXoU4WsJcQ220dRGHDhHjmYEIXPeBCm7nJSVSr97vMMNdKgWzIeDvERhWJSfUxTBN test@example.com"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "latest"
  }

  tags = {
    Purpose     = "nebula-vm-userdata-secrets-testing"
    Module      = "vm-userdata-secrets"
    SecretTypes = "jwt-tokens,database-urls,redis-passwords"
  }
}

# Outputs
output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "vm_names" {
  value = [
    azurerm_linux_virtual_machine.test.name,
    azurerm_linux_virtual_machine.test_custom.name
  ]
}

output "test_instructions" {
  value = <<-EOT
    VM UserData Secrets Testing Infrastructure Created
    
    Resource Group: ${azurerm_resource_group.test.name}
    VMs Created:
    - ${azurerm_linux_virtual_machine.test.name} (user_data with multiple secret types)
    - ${azurerm_linux_virtual_machine.test_custom.name} (custom_data with additional patterns)
    
    To test VM userdata secret scanning:
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Compute/virtualMachines/userData
    
    Expected Findings:
    - Database passwords and connection strings
    - API keys (AWS, Azure, GitHub, Slack, SendGrid)
    - JWT tokens and OAuth secrets
    - Private keys and SSL certificates
    - Redis and MongoDB connection strings
    - Various service credentials
  EOT
}