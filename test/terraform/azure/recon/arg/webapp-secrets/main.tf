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
  features {}
}

locals {
  random_suffix = random_string.suffix.result
  name_prefix   = "test-webapp"
  location      = "Central US"
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Resource group for Web App secrets testing
resource "azurerm_resource_group" "test" {
  name     = "${local.name_prefix}-${local.random_suffix}"
  location = local.location

  tags = {
    Purpose = "nebula-webapp-secrets-testing"
    Module  = "webapp-secrets"
  }
}

# App Service Plan
resource "azurerm_service_plan" "test" {
  name                = "${local.name_prefix}-asp-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
}

# Linux Web App with extensive app settings containing secrets
resource "azurerm_linux_web_app" "test" {
  name                = "${local.name_prefix}-app-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_service_plan.test.location
  service_plan_id     = azurerm_service_plan.test.id

  site_config {
    application_stack {
      node_version = "18-lts"
    }
  }

  # Application settings with various types of secrets
  app_settings = {
    # Database credentials
    "DATABASE_PASSWORD"    = "webapp-db-secret-${local.random_suffix}"
    "DB_CONNECTION_STRING" = "Server=testserver.database.windows.net;Database=testdb;User ID=webapp;Password=webapp-db-password-${local.random_suffix};"
    "POSTGRES_URL"         = "postgresql://user:webapp-postgres-${local.random_suffix}@localhost:5432/mydb"
    "MONGODB_URI"          = "mongodb://user:webapp-mongo-${local.random_suffix}@localhost:27017/testdb"
    "REDIS_URL"            = "redis://:webapp-redis-${local.random_suffix}@localhost:6379"

    # API Keys and tokens
    "API_SECRET_KEY"      = "webapp-api-secret-${local.random_suffix}"
    "JWT_SECRET"          = "webapp-jwt-secret-${local.random_suffix}"
    "OAUTH_CLIENT_SECRET" = "webapp-oauth-secret-${local.random_suffix}"
    "BEARER_TOKEN"        = "Bearer webapp-bearer-token-${local.random_suffix}"

    # Cloud service credentials
    "AZURE_CLIENT_SECRET"   = "webapp-azure-secret-${local.random_suffix}"
    "AWS_SECRET_ACCESS_KEY" = "webapp-aws-secret-${local.random_suffix}"
    "GCP_PRIVATE_KEY"       = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VGmBq...\n-----END PRIVATE KEY-----"

    # Third-party service keys
    "SENDGRID_API_KEY"  = "SG.webapp-sendgrid-key-${local.random_suffix}"
    "STRIPE_SECRET_KEY" = "sk_test_webapp_stripe_${local.random_suffix}"
    "TWILIO_AUTH_TOKEN" = "webapp-twilio-token-${local.random_suffix}"
    "SLACK_BOT_TOKEN"   = "xoxb-webapp-slack-token-${local.random_suffix}"
    "GITHUB_TOKEN"      = "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"

    # Encryption and signing keys
    "ENCRYPTION_KEY" = "webapp-encryption-key-${local.random_suffix}"
    "SIGNING_KEY"    = "webapp-signing-key-${local.random_suffix}"
    "WEBHOOK_SECRET" = "webapp-webhook-secret-${local.random_suffix}"

    # Storage and file service keys
    "STORAGE_ACCOUNT_KEY"     = "webapp-storage-key-${local.random_suffix}"
    "BLOB_STORAGE_CONNECTION" = "DefaultEndpointsProtocol=https;AccountName=webapptest;AccountKey=webapp-blob-key-${local.random_suffix};EndpointSuffix=core.windows.net"
    "S3_SECRET_KEY"           = "webapp-s3-secret-${local.random_suffix}"

    # Monitoring and logging
    "APP_INSIGHTS_KEY"  = "webapp-insights-key-${local.random_suffix}"
    "LOG_ANALYTICS_KEY" = "webapp-log-key-${local.random_suffix}"
    "DATADOG_API_KEY"   = "webapp-datadog-key-${local.random_suffix}"
  }

  # Connection strings with sensitive information
  connection_string {
    name  = "DefaultConnection"
    type  = "SQLServer"
    value = "Server=tcp:webapp-server.database.windows.net,1433;Database=webapp-db;User ID=webapp-admin;Password=webapp-conn-password-${local.random_suffix};Encrypt=true;Connection Timeout=30;"
  }

  connection_string {
    name  = "RedisConnection"
    type  = "Custom"
    value = "webapp-redis-host:6379,password=webapp-redis-conn-${local.random_suffix},ssl=False,abortConnect=False"
  }

  connection_string {
    name  = "StorageConnection"
    type  = "Custom"
    value = "DefaultEndpointsProtocol=https;AccountName=webappstore;AccountKey=webapp-storage-conn-${local.random_suffix};EndpointSuffix=core.windows.net"
  }

  connection_string {
    name  = "MongoConnection"
    type  = "Custom"
    value = "mongodb://webapp-user:webapp-mongo-conn-${local.random_suffix}@webapp-mongo-cluster.cosmos.azure.com:10255/webapp-db?ssl=true&retrywrites=false&maxIdleTimeMS=120000&appName=@webapp-mongo-cluster@"
  }

  tags = {
    Purpose     = "nebula-webapp-secrets-testing"
    Module      = "webapp-secrets"
    SecretTypes = "database-passwords,api-keys,connection-strings,oauth-secrets"
  }
}

# Function App with additional secret patterns
resource "azurerm_linux_function_app" "test" {
  name                       = "${local.name_prefix}-func-${local.random_suffix}"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_service_plan.test.location
  service_plan_id            = azurerm_service_plan.test.id
  storage_account_name       = azurerm_storage_account.test.name
  storage_account_access_key = azurerm_storage_account.test.primary_access_key

  site_config {
    application_stack {
      node_version = "18"
    }
  }

  # Function app settings with secrets
  app_settings = {
    # Function-specific secrets
    "FUNCTIONS_WORKER_RUNTIME"     = "node"
    "WEBSITE_NODE_DEFAULT_VERSION" = "~18"
    "FUNCTION_APP_EDIT_MODE"       = "readwrite"

    # Database secrets for functions
    "COSMOS_DB_CONNECTION"  = "AccountEndpoint=https://func-cosmos.documents.azure.com:443/;AccountKey=func-cosmos-key-${local.random_suffix};"
    "SQL_CONNECTION_STRING" = "Server=func-sql.database.windows.net;Database=func-db;User=func-user;Password=func-sql-password-${local.random_suffix};"

    # Service Bus and Event Hub secrets
    "SERVICE_BUS_CONNECTION" = "Endpoint=sb://func-sb.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=func-sb-key-${local.random_suffix}"
    "EVENT_HUB_CONNECTION"   = "Endpoint=sb://func-eh.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=func-eh-key-${local.random_suffix}"

    # External service integrations
    "THIRD_PARTY_API_KEY"       = "func-third-party-${local.random_suffix}"
    "WEBHOOK_VALIDATION_SECRET" = "func-webhook-secret-${local.random_suffix}"
    "OAUTH_CLIENT_SECRET"       = "func-oauth-secret-${local.random_suffix}"
  }

  tags = {
    Purpose     = "nebula-webapp-secrets-testing"
    Module      = "webapp-secrets"
    SecretTypes = "cosmos-db,service-bus,event-hub,oauth"
  }
}

# Storage account for function app
resource "azurerm_storage_account" "test" {
  name                     = "webapp${local.random_suffix}"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    Purpose = "nebula-webapp-secrets-testing"
    Module  = "webapp-secrets"
  }
}

# Windows Web App for additional testing scenarios
resource "azurerm_service_plan" "windows" {
  name                = "${local.name_prefix}-win-asp-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Windows"
  sku_name            = "B1"
}

resource "azurerm_windows_web_app" "test" {
  name                = "${local.name_prefix}-win-${local.random_suffix}"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_service_plan.windows.location
  service_plan_id     = azurerm_service_plan.windows.id

  site_config {
    application_stack {
      dotnet_version = "v6.0"
    }
  }

  # Windows-specific app settings
  app_settings = {
    # .NET specific secrets
    "ConnectionStrings__DefaultConnection"    = "Server=win-server.database.windows.net;Database=win-db;User Id=win-user;Password=win-password-${local.random_suffix};"
    "Authentication__Google__ClientSecret"    = "win-google-secret-${local.random_suffix}"
    "Authentication__Facebook__AppSecret"     = "win-facebook-secret-${local.random_suffix}"
    "Authentication__Microsoft__ClientSecret" = "win-microsoft-secret-${local.random_suffix}"

    # Windows service credentials
    "ServiceCredentials__Username" = "win-service-user-${local.random_suffix}"
    "ServiceCredentials__Password" = "win-service-password-${local.random_suffix}"
    "CertificatePassword"          = "win-cert-password-${local.random_suffix}"

    # Windows-specific integrations
    "ActiveDirectory__ClientSecret" = "win-ad-secret-${local.random_suffix}"
    "Exchange__Password"            = "win-exchange-password-${local.random_suffix}"
    "SharePoint__ClientSecret"      = "win-sharepoint-secret-${local.random_suffix}"
  }

  connection_string {
    name  = "EntityFramework"
    type  = "SQLServer"
    value = "Server=win-ef-server.database.windows.net;Database=win-ef-db;User ID=win-ef-user;Password=win-ef-password-${local.random_suffix};Encrypt=true;"
  }

  tags = {
    Purpose     = "nebula-webapp-secrets-testing"
    Module      = "webapp-secrets"
    SecretTypes = "dotnet-secrets,authentication-providers,active-directory"
  }
}

# Outputs
output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

output "web_app_names" {
  value = [
    azurerm_linux_web_app.test.name,
    azurerm_linux_function_app.test.name,
    azurerm_windows_web_app.test.name
  ]
}

output "test_instructions" {
  value = <<-EOT
    Web App Secrets Testing Infrastructure Created
    
    Resource Group: ${azurerm_resource_group.test.name}
    Web Apps:
    - ${azurerm_linux_web_app.test.name} (Linux web app with extensive app settings)
    - ${azurerm_linux_function_app.test.name} (Function app with service integrations)
    - ${azurerm_windows_web_app.test.name} (Windows web app with .NET-specific secrets)
    
    To test web app secrets scanning:
    
    # Test app settings
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Web/sites/configuration
    
    # Test connection strings
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Web/sites/connectionStrings
    
    # Test web app keys
    go run main.go azure recon find-secrets \
      --subscription 355e78a0-4c5e-4de3-9980-6a35cae86f01 \
      --resource-types Microsoft.Web/sites/keys
    
    Expected Findings:
    - Database passwords and connection strings (SQL Server, PostgreSQL, MongoDB, Redis)
    - API keys and tokens (JWT, OAuth, Bearer tokens)
    - Cloud service credentials (Azure, AWS, GCP)
    - Third-party service keys (SendGrid, Stripe, Twilio, Slack, GitHub)
    - Encryption and signing keys
    - Storage account keys and connection strings
    - Service Bus and Event Hub connection strings
    - Authentication provider secrets (Google, Facebook, Microsoft)
    - Windows-specific credentials (Active Directory, Exchange, SharePoint)
    - Certificate passwords and service account credentials
  EOT
}