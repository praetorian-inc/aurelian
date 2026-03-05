terraform {
  backend "s3" {}
}

locals {
  random_suffix = random_string.suffix.result
  name_prefix   = "test-automation"
  location      = "Central US"
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

# Resource group for Automation Account secrets testing
resource "azurerm_resource_group" "test" {
  name     = "${local.name_prefix}-${local.random_suffix}"
  location = local.location

  tags = {
    Purpose = "nebula-automation-secrets-testing"
    Module  = "automation-secrets"
  }
}

# Automation Account
resource "azurerm_automation_account" "test" {
  name                = "${local.name_prefix}-aa-${local.random_suffix}"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  sku_name            = "Basic"

  tags = {
    Purpose = "nebula-automation-secrets-testing"
    Module  = "automation-secrets"
  }
}

# PowerShell Runbook with embedded secrets
resource "azurerm_automation_runbook" "powershell_secrets" {
  name                    = "PowerShell-Secrets-${local.random_suffix}"
  location                = azurerm_resource_group.test.location
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  log_verbose             = true
  log_progress            = true
  description             = "PowerShell runbook with embedded secrets for testing"
  runbook_type            = "PowerShell"

  content = <<-EOF
    # PowerShell runbook with various secret patterns
    
    # Database credentials
    $DatabasePassword = "ps-db-secret-${local.random_suffix}"
    $ConnectionString = "Server=ps-server.database.windows.net;Database=ps-db;User Id=ps-user;Password=ps-password-${local.random_suffix};"
    
    # API keys and tokens
    $ApiKey = "ps-api-key-${local.random_suffix}"
    $SecretToken = "ps-bearer-token-${local.random_suffix}"
    $OAuthSecret = "ps-oauth-secret-${local.random_suffix}"
    
    # Azure service principal credentials
    $ClientSecret = "ps-client-secret-${local.random_suffix}"
    $TenantId = "ps-tenant-id-${local.random_suffix}"
    $ApplicationId = "ps-app-id-${local.random_suffix}"
    
    # Storage and service keys
    $StorageAccountKey = "ps-storage-key-${local.random_suffix}"
    $CosmosDbKey = "ps-cosmos-key-${local.random_suffix}"
    $ServiceBusConnectionString = "Endpoint=sb://ps-sb.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ps-sb-key-${local.random_suffix}"
    
    # Third-party service credentials
    $SendGridApiKey = "SG.ps-sendgrid-key-${local.random_suffix}"
    $SlackToken = "xoxb-ps-slack-token-${local.random_suffix}"
    $GitHubToken = "ghp_ps_github_token_${local.random_suffix}"
    
    # Encryption and signing keys
    $EncryptionKey = "ps-encryption-key-${local.random_suffix}"
    $JwtSecret = "ps-jwt-secret-${local.random_suffix}"
    $WebhookSecret = "ps-webhook-secret-${local.random_suffix}"
    
    Write-Output "Starting PowerShell automation with embedded secrets..."
    
    # Connection examples with credentials
    try {
        # SQL Server connection
        $SqlCredential = New-Object System.Management.Automation.PSCredential("ps-sql-user", (ConvertTo-SecureString "ps-sql-password-${local.random_suffix}" -AsPlainText -Force))
        
        # Azure connection using service principal
        $AzureCredential = New-Object System.Management.Automation.PSCredential($ApplicationId, (ConvertTo-SecureString $ClientSecret -AsPlainText -Force))
        
        # REST API call with authentication
        $Headers = @{
            'Authorization' = "Bearer $SecretToken"
            'X-API-Key' = $ApiKey
        }
        
        Write-Output "Connections established successfully"
    }
    catch {
        Write-Error "Failed to establish connections: $_"
    }
    
    # Certificate handling
    $CertificatePassword = "ps-cert-password-${local.random_suffix}"
    $CertificateThumbprint = "ps-cert-thumbprint-${local.random_suffix}"
    
    Write-Output "PowerShell runbook execution completed"
  EOF

  tags = {
    Purpose     = "nebula-automation-secrets-testing"
    Module      = "automation-secrets"
    RunbookType = "PowerShell"
  }
}

# Python Runbook with different secret patterns
resource "azurerm_automation_runbook" "python_secrets" {
  name                    = "Python-Secrets-${local.random_suffix}"
  location                = azurerm_resource_group.test.location
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  log_verbose             = true
  log_progress            = true
  description             = "Python runbook with embedded secrets for testing"
  runbook_type            = "Python3"

  content = <<-EOF
    import os
    import json
    import base64
    
    # Python runbook with various secret patterns
    
    # Database credentials
    DB_PASSWORD = "py-db-secret-${local.random_suffix}"
    CONNECTION_STRING = "postgresql://py-user:py-password-${local.random_suffix}@py-server:5432/py-db"
    MONGODB_URI = "mongodb://py-user:py-mongo-${local.random_suffix}@py-mongo:27017/py-db"
    
    # API credentials
    API_KEY = "py-api-key-${local.random_suffix}"
    SECRET_TOKEN = "py-bearer-token-${local.random_suffix}"
    OAUTH_CLIENT_SECRET = "py-oauth-secret-${local.random_suffix}"
    
    # Cloud service credentials
    AZURE_CLIENT_SECRET = "py-azure-secret-${local.random_suffix}"
    AWS_SECRET_ACCESS_KEY = "py-aws-secret-${local.random_suffix}"
    GCP_SERVICE_ACCOUNT_KEY = '''
    {
      "type": "service_account",
      "project_id": "py-test-project",
      "private_key_id": "py-key-id-${local.random_suffix}",
      "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VGmBq...\\n-----END PRIVATE KEY-----\\n",
      "client_email": "py-service@py-test-project.iam.gserviceaccount.com",
      "client_id": "py-client-id-${local.random_suffix}"
    }
    '''
    
    # Service integrations
    SENDGRID_API_KEY = "SG.py-sendgrid-key-${local.random_suffix}"
    STRIPE_SECRET_KEY = "sk_test_py_stripe_${local.random_suffix}"
    TWILIO_AUTH_TOKEN = "py-twilio-token-${local.random_suffix}"
    SLACK_BOT_TOKEN = "xoxb-py-slack-token-${local.random_suffix}"
    
    # Storage and messaging
    STORAGE_ACCOUNT_KEY = "py-storage-key-${local.random_suffix}"
    REDIS_PASSWORD = "py-redis-password-${local.random_suffix}"
    RABBITMQ_PASSWORD = "py-rabbitmq-password-${local.random_suffix}"
    
    # Encryption and security
    ENCRYPTION_KEY = "py-encryption-key-${local.random_suffix}"
    JWT_SECRET = "py-jwt-secret-${local.random_suffix}"
    WEBHOOK_SECRET = "py-webhook-secret-${local.random_suffix}"
    
    print("Starting Python automation with embedded secrets...")
    
    # Configuration dictionary with secrets
    config = {
        "database": {
            "host": "py-db-host",
            "password": f"py-db-config-password-{local.random_suffix}",
            "connection_string": CONNECTION_STRING
        },
        "services": {
            "redis": f"redis://:py-redis-config-{local.random_suffix}@localhost:6379",
            "mongodb": MONGODB_URI,
            "storage": {
                "account_name": "py-storage",
                "account_key": STORAGE_ACCOUNT_KEY
            }
        },
        "api_keys": {
            "sendgrid": SENDGRID_API_KEY,
            "stripe": STRIPE_SECRET_KEY,
            "twilio": TWILIO_AUTH_TOKEN
        }
    }
    
    # Base64 encoded secrets (common pattern)
    encoded_secret = base64.b64encode(f"py-encoded-secret-{local.random_suffix}".encode()).decode()
    
    print("Python runbook execution completed")
    print(f"Configuration loaded with {len(config)} sections")
  EOF

  tags = {
    Purpose     = "nebula-automation-secrets-testing"
    Module      = "automation-secrets"
    RunbookType = "Python3"
  }
}

# GraphQL Runbook with API secrets
resource "azurerm_automation_runbook" "graphql_secrets" {
  name                    = "GraphQL-Secrets-${local.random_suffix}"
  location                = azurerm_resource_group.test.location
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  log_verbose             = true
  log_progress            = true
  description             = "GraphQL runbook with API secrets for testing"
  runbook_type            = "PowerShell"

  content = <<-EOF
    # GraphQL PowerShell runbook with API integrations
    
    # API endpoint credentials
    $GraphQLEndpoint = "https://api.example.com/graphql"
    $ApiToken = "gql-bearer-token-${local.random_suffix}"
    $ClientId = "gql-client-id-${local.random_suffix}"
    $ClientSecret = "gql-client-secret-${local.random_suffix}"
    
    # Database connection for GraphQL backend
    $DatabaseUrl = "postgresql://gql-user:gql-password-${local.random_suffix}@gql-server:5432/gql-db"
    
    # Authentication headers
    $Headers = @{
        'Authorization' = "Bearer $ApiToken"
        'X-Client-ID' = $ClientId
        'X-Client-Secret' = $ClientSecret
        'Content-Type' = 'application/json'
    }
    
    # GraphQL mutation with embedded credentials
    $MutationQuery = @"
    mutation CreateUser {
      createUser(input: {
        username: "test-user"
        password: "gql-user-password-${local.random_suffix}"
        apiKey: "gql-user-api-key-${local.random_suffix}"
      }) {
        id
        username
      }
    }
    "@
    
    # Service configuration with secrets
    $ServiceConfig = @{
        redis = @{
            host = "gql-redis-host"
            password = "gql-redis-password-${local.random_suffix}"
        }
        elasticsearch = @{
            url = "https://gql-es-user:gql-es-password-${local.random_suffix}@elasticsearch:9200"
        }
        mongodb = @{
            uri = "mongodb://gql-mongo-user:gql-mongo-password-${local.random_suffix}@mongo:27017/gql-db"
        }
    }
    
    Write-Output "Starting GraphQL automation with embedded secrets..."
    Write-Output "GraphQL runbook execution completed"
  EOF

  tags = {
    Purpose     = "nebula-automation-secrets-testing"
    Module      = "automation-secrets"
    RunbookType = "GraphPowerShell"
  }
}

# Automation Variables with secret values
resource "azurerm_automation_variable_string" "db_connection" {
  name                    = "DatabaseConnectionString"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "Server=var-server.database.windows.net;Database=var-db;User ID=var-user;Password=var-password-${local.random_suffix};Encrypt=true;"
  description             = "Database connection string with embedded password"
}

resource "azurerm_automation_variable_string" "api_key" {
  name                    = "ApiSecretKey"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "var-api-secret-key-${local.random_suffix}"
  description             = "API secret key for external service integration"
}

resource "azurerm_automation_variable_string" "github_token" {
  name                    = "GitHubToken"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "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"
  description             = "GitHub personal access token for repository access"
}

resource "azurerm_automation_variable_string" "service_principal" {
  name                    = "ServicePrincipalSecret"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "var-sp-secret-${local.random_suffix}"
  description             = "Azure service principal secret for authentication"
}

resource "azurerm_automation_variable_string" "storage_key" {
  name                    = "StorageAccountKey"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "var-storage-key-${local.random_suffix}"
  description             = "Storage account access key"
}

resource "azurerm_automation_variable_string" "oauth_config" {
  name                    = "OAuthConfiguration"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value = jsonencode({
    client_id     = "var-oauth-client-${local.random_suffix}"
    client_secret = "var-oauth-secret-${local.random_suffix}"
    tenant_id     = "var-tenant-id-${local.random_suffix}"
    scope         = "https://graph.microsoft.com/.default"
  })
  description = "OAuth configuration with client secret"
}

resource "azurerm_automation_variable_string" "encryption_keys" {
  name                    = "EncryptionKeys"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value = jsonencode({
    primary_key    = "var-primary-encryption-${local.random_suffix}"
    secondary_key  = "var-secondary-encryption-${local.random_suffix}"
    jwt_secret     = "var-jwt-secret-${local.random_suffix}"
    webhook_secret = "var-webhook-secret-${local.random_suffix}"
  })
  description = "Encryption keys configuration"
}

# Encrypted automation variables (still contain secrets in encrypted form)
resource "azurerm_automation_variable_string" "encrypted_password" {
  name                    = "EncryptedDatabasePassword"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "encrypted-db-password-${local.random_suffix}"
  description             = "Encrypted database password"
  encrypted               = true
}

resource "azurerm_automation_variable_string" "encrypted_api_key" {
  name                    = "EncryptedApiKey"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = "encrypted-api-key-${local.random_suffix}"
  description             = "Encrypted API key"
  encrypted               = true
}

# Integer and boolean variables that might contain sensitive IDs
resource "azurerm_automation_variable_int" "sensitive_id" {
  name                    = "SensitiveServiceId"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = 123456789
  description             = "Sensitive service identifier"
}

resource "azurerm_automation_variable_bool" "debug_mode" {
  name                    = "DebugModeEnabled"
  resource_group_name     = azurerm_resource_group.test.name
  automation_account_name = azurerm_automation_account.test.name
  value                   = true
  description             = "Debug mode flag (might reveal sensitive information in logs)"
}

# Outputs
output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "automation_account_name" {
  value = azurerm_automation_account.test.name
}

output "runbook_names" {
  value = [
    azurerm_automation_runbook.powershell_secrets.name,
    azurerm_automation_runbook.python_secrets.name,
    azurerm_automation_runbook.graphql_secrets.name
  ]
}

output "variable_names" {
  value = [
    azurerm_automation_variable_string.db_connection.name,
    azurerm_automation_variable_string.api_key.name,
    azurerm_automation_variable_string.github_token.name,
    azurerm_automation_variable_string.service_principal.name,
    azurerm_automation_variable_string.storage_key.name,
    azurerm_automation_variable_string.oauth_config.name,
    azurerm_automation_variable_string.encryption_keys.name,
    azurerm_automation_variable_string.encrypted_password.name,
    azurerm_automation_variable_string.encrypted_api_key.name
  ]
}

output "test_instructions" {
  value = <<-EOT
    Automation Account Secrets Testing Infrastructure Created
    
    Resource Group: ${azurerm_resource_group.test.name}
    Automation Account: ${azurerm_automation_account.test.name}
    
    Runbooks:
    - ${azurerm_automation_runbook.powershell_secrets.name} (PowerShell with database, API, Azure credentials)
    - ${azurerm_automation_runbook.python_secrets.name} (Python with cloud services, storage, messaging)
    - ${azurerm_automation_runbook.graphql_secrets.name} (GraphQL with API tokens, database connections)
    
    Variables:
    - String variables with connection strings, API keys, OAuth config
    - Encrypted variables with passwords and keys
    - JSON configuration variables with embedded secrets
    
    To test automation secrets scanning:
    
    # Test runbooks
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Automation/automationAccounts/runbooks
    
    # Test variables
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Automation/automationAccounts/variables
    
    # Test jobs (if any jobs are created)
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Automation/automationAccounts/jobs
    
    Expected Findings:
    - Database passwords and connection strings in runbooks
    - API keys and bearer tokens in PowerShell/Python scripts
    - Azure service principal secrets
    - Cloud service credentials (AWS, GCP, Azure)
    - Third-party service keys (SendGrid, Stripe, Twilio, Slack, GitHub)
    - Storage account keys and connection strings
    - Encryption keys and JWT secrets
    - OAuth client secrets and configurations
    - JSON configuration objects with embedded secrets
    - Base64 encoded secrets
    - Certificate passwords and service credentials
  EOT
}