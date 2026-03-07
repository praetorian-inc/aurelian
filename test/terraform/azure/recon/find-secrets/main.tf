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
// | 5  | Container Instance      | environment variable                 | DETECTED        |
// | 6  | App Configuration Store | key-value pair                       | DETECTED        |
// | 7  | Logic App (Consumption) | workflow parameter                   | DETECTED        |
// | 8  | Data Factory            | linked service Basic auth + pipeline | DETECTED        |
// | 9  | Storage Account         | resource tag                         | DETECTED        |
// | 10 | Policy Definition       | metadata field                       | DETECTED        |
// | 11 | ARM Template Deployment | parameters_content                   | DETECTED        |
// | 12 | Template Spec (azapi)   | defaultValue in ARM template         | DETECTED        |
// | 13 | VMSS                    | user_data + extension                | DETECTED        |
// | 14 | Container App           | environment variable                 | DETECTED        |
// | 15 | Static Web App          | app settings (azapi)                 | DETECTED        |
// | 16 | Application Insights    | (shared Log Analytics workspace)     | DETECTED        |
// | 17 | Batch Account + Pool    | start task env var + command line     | DETECTED        |
// | 18 | Container Registry Task | encoded task content (azapi)         | DETECTED        |
// | 19 | Cosmos DB               | stored proc, trigger, UDF            | DETECTED        |
// | 20 | Digital Twins           | resource tag                         | DETECTED        |
// | 21 | Synapse Workspace       | resource tag                         | DETECTED        |
// | 22 | APIM                    | named value, backend, policy         | DETECTED        |

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
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
    azapi = {
      source  = "azure/azapi"
      version = "~> 1.0"
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

resource "azurerm_storage_account" "bootdiag" {
  name                     = "${local.prefix_san}bd"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags
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

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.bootdiag.primary_blob_endpoint
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  tags = local.tags
}

resource "azurerm_virtual_machine_extension" "test" {
  name                 = "${local.prefix}-vmext"
  virtual_machine_id   = azurerm_linux_virtual_machine.test.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.1"

  settings = jsonencode({
    commandToExecute = "echo AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
  })
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
  sku_name            = "S1"
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

  connection_string {
    name  = "Database"
    type  = "SQLAzure"
    value = "Server=tcp:example.database.windows.net;Database=mydb;User ID=admin;Password=${local.fake_aws_secret};Encrypt=true;"
  }

  tags = local.tags
}

resource "azurerm_linux_web_app_slot" "staging" {
  name           = "staging"
  app_service_id = azurerm_linux_web_app.test.id

  site_config {}

  app_settings = {
    "STAGING_SECRET_KEY" = local.fake_aws_secret
  }

  tags = local.tags
}

resource "azurerm_linux_function_app" "test" {
  name                       = "${local.prefix}-func"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  service_plan_id            = azurerm_service_plan.test.id
  storage_account_name       = azurerm_storage_account.test.name
  storage_account_access_key = azurerm_storage_account.test.primary_access_key

  site_config {
    application_stack {
      node_version = "18"
    }
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

resource "azurerm_automation_runbook" "test" {
  name                    = "${local.prefix}-runbook"
  resource_group_name     = azurerm_resource_group.test.name
  location                = azurerm_resource_group.test.location
  automation_account_name = azurerm_automation_account.test.name
  log_verbose             = false
  log_progress            = false
  runbook_type            = "PowerShell"

  content = <<-PS
    # PowerShell runbook with embedded credentials
    $awsKey    = "${local.fake_aws_key}"
    $awsSecret = "${local.fake_aws_secret}"
    Write-Output "Configured AWS credentials"
  PS

  tags = local.tags
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
  tags                     = merge(local.tags, { "api-key" = local.fake_aws_secret })
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

# ============================================================
# 5. Container Instance — secret in env var
# ============================================================
resource "azurerm_container_group" "test" {
  name                = "${local.prefix}-ci"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  ip_address_type     = "None"

  container {
    name   = "test"
    image  = "mcr.microsoft.com/azuredocs/aci-helloworld:latest"
    cpu    = "0.5"
    memory = "0.5"

    environment_variables = {
      AWS_ACCESS_KEY_ID     = local.fake_aws_key
      AWS_SECRET_ACCESS_KEY = local.fake_aws_secret
    }
  }
  tags = local.tags
}

# ============================================================
# 6. App Configuration Store — key-value with secret
# ============================================================
resource "azurerm_app_configuration" "test" {
  name                = "${local.prefix}-appconfig"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "free"
  tags                = local.tags
}

resource "azurerm_role_assignment" "appconfig_data_owner" {
  scope                = azurerm_app_configuration.test.id
  role_definition_name = "App Configuration Data Owner"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "time_sleep" "appconfig_rbac_propagation" {
  depends_on      = [azurerm_role_assignment.appconfig_data_owner]
  create_duration = "60s"
}

resource "azurerm_app_configuration_key" "secret" {
  configuration_store_id = azurerm_app_configuration.test.id
  key                    = "database/connection-string"
  value                  = "Server=tcp:example.database.windows.net;Password=${local.fake_aws_secret};Encrypt=true;"
  depends_on             = [time_sleep.appconfig_rbac_propagation]
}

# ============================================================
# 7. Logic App (Consumption) — secret in workflow definition
# ============================================================
resource "azurerm_logic_app_workflow" "test" {
  name                = "${local.prefix}-logic"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags

  workflow_parameters = {
    "secretParam" = jsonencode({
      type         = "String"
      defaultValue = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
    })
  }
}

# ============================================================
# 8. Data Factory — linked service with connection string
# ============================================================
resource "azurerm_data_factory" "test" {
  name                = "${local.prefix}-adf"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

resource "azurerm_data_factory_linked_service_web" "test" {
  name                = "test-web-linked-service"
  data_factory_id     = azurerm_data_factory.test.id
  authentication_type = "Basic"
  url                 = "https://example.com/api"
  username            = local.fake_aws_key
  password            = local.fake_aws_secret
}

resource "azapi_resource" "adf_pipeline" {
  type      = "Microsoft.DataFactory/factories/pipelines@2018-06-01"
  name      = "test-pipeline"
  parent_id = azurerm_data_factory.test.id

  body = jsonencode({
    properties = {
      activities = [
        {
          name = "SetSecret"
          type = "SetVariable"
          typeProperties = {
            variableName = "secretVar"
            value        = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
          }
        }
      ]
      variables = {
        secretVar = {
          type         = "String"
          defaultValue = ""
        }
      }
    }
  })
}

# ============================================================
# 10. Policy Definition — secret in metadata
# ============================================================
resource "azurerm_policy_definition" "test" {
  name         = "${local.prefix}-policy"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Test policy with embedded secret"

  policy_rule = jsonencode({
    if = {
      field  = "type"
      equals = "Microsoft.Resources/subscriptions"
    }
    then = {
      effect = "audit"
    }
  })

  metadata = jsonencode({
    category    = "Testing"
    description = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
  })
}

# ============================================================
# 11. ARM Template Deployment — secret in parameters
# ============================================================
resource "azurerm_resource_group_template_deployment" "test" {
  name                = "${local.prefix}-deploy"
  resource_group_name = azurerm_resource_group.test.name
  deployment_mode     = "Incremental"

  parameters_content = jsonencode({
    secretParam = {
      value = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
    }
  })

  template_content = jsonencode({
    "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    parameters = {
      secretParam = {
        type = "string"
      }
    }
    resources = []
    outputs = {
      result = {
        type  = "string"
        value = "[parameters('secretParam')]"
      }
    }
  })
}

# ============================================================
# 12. Template Spec (azapi) — secret in ARM template default
# ============================================================
resource "azapi_resource" "template_spec" {
  type      = "Microsoft.Resources/templateSpecs@2022-02-01"
  name      = "${local.prefix}-tspec"
  parent_id = azurerm_resource_group.test.id
  location  = local.location
  tags      = local.tags

  body = jsonencode({
    properties = {
      description = "Test template spec"
    }
  })
}

resource "azapi_resource" "template_spec_version" {
  type      = "Microsoft.Resources/templateSpecs/versions@2022-02-01"
  name      = "v1.0"
  parent_id = azapi_resource.template_spec.id
  location  = local.location
  tags      = local.tags

  body = jsonencode({
    properties = {
      mainTemplate = {
        "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
        contentVersion = "1.0.0.0"
        parameters = {
          dbPassword = { type = "string", defaultValue = local.fake_aws_secret }
        }
        resources = []
      }
    }
  })
}

# ============================================================
# 13. VMSS — secret in user_data and extension (0 instances)
# ============================================================
resource "azurerm_linux_virtual_machine_scale_set" "test" {
  name                            = "${local.prefix}-vmss"
  resource_group_name             = azurerm_resource_group.test.name
  location                        = azurerm_resource_group.test.location
  sku                             = "Standard_B1ls"
  instances                       = 0
  admin_username                  = "aurelianadmin"
  admin_password                  = "P@ssw0rd${random_string.suffix.result}!"
  disable_password_authentication = false

  user_data = base64encode(<<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="${local.fake_aws_key}"
    export AWS_SECRET_ACCESS_KEY="${local.fake_aws_secret}"
  EOF
  )

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  network_interface {
    name    = "vmss-nic"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = azurerm_subnet.test.id
    }
  }

  extension {
    name                 = "test-script"
    publisher            = "Microsoft.Azure.Extensions"
    type                 = "CustomScript"
    type_handler_version = "2.1"

    settings = jsonencode({
      commandToExecute = "echo AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
    })
  }

  tags = local.tags
}

# ============================================================
# 14. Log Analytics Workspace (shared by Container App + App Insights)
# ============================================================
resource "azurerm_log_analytics_workspace" "test" {
  name                = "${local.prefix}-law"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

# ============================================================
# 15. Container App Environment + Container App with env vars
# ============================================================
resource "azurerm_container_app_environment" "test" {
  name                       = "${local.prefix}-cae"
  resource_group_name        = azurerm_resource_group.test.name
  location                   = azurerm_resource_group.test.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.test.id
  tags                       = local.tags
}

resource "azurerm_container_app" "test" {
  name                         = "${local.prefix}-ca"
  resource_group_name          = azurerm_resource_group.test.name
  container_app_environment_id = azurerm_container_app_environment.test.id
  revision_mode                = "Single"
  tags                         = local.tags

  template {
    min_replicas = 0
    max_replicas = 1

    container {
      name   = "test"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "AWS_ACCESS_KEY_ID"
        value = local.fake_aws_key
      }
      env {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = local.fake_aws_secret
      }
    }
  }
}

# ============================================================
# 16. Static Web App + app settings via azapi
# ============================================================
resource "azurerm_static_web_app" "test" {
  name                = "${local.prefix}-swa"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku_tier            = "Free"
  sku_size            = "Free"
  tags                = local.tags
}

resource "azapi_update_resource" "swa_settings" {
  type      = "Microsoft.Web/staticSites/config@2022-09-01"
  name      = "appsettings"
  parent_id = azurerm_static_web_app.test.id

  body = jsonencode({
    properties = {
      AWS_ACCESS_KEY_ID     = local.fake_aws_key
      AWS_SECRET_ACCESS_KEY = local.fake_aws_secret
    }
  })
}

# ============================================================
# 17. Application Insights
# ============================================================
resource "azurerm_application_insights" "test" {
  name                = "${local.prefix}-ai"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  workspace_id        = azurerm_log_analytics_workspace.test.id
  application_type    = "web"
  tags                = local.tags
}

# ============================================================
# 18. Batch Account + Pool with start task containing secrets
# ============================================================
resource "azurerm_batch_account" "test" {
  name                                = "${local.prefix_san}ba"
  resource_group_name                 = azurerm_resource_group.test.name
  location                            = azurerm_resource_group.test.location
  pool_allocation_mode                = "BatchService"
  storage_account_id                  = azurerm_storage_account.test.id
  storage_account_authentication_mode = "StorageKeys"
  tags                                = local.tags
}

resource "azurerm_batch_pool" "test" {
  name                = "testpool"
  resource_group_name = azurerm_resource_group.test.name
  account_name        = azurerm_batch_account.test.name
  display_name        = "Test Pool"
  vm_size             = "Standard_A1_v2"
  node_agent_sku_id   = "batch.node.ubuntu 22.04"

  fixed_scale {
    target_dedicated_nodes = 0
  }

  storage_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  start_task {
    command_line = "/bin/bash -c 'export AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret} && echo configured'"

    user_identity {
      auto_user {
        elevation_level = "NonAdmin"
        scope           = "Task"
      }
    }
  }
}

# ============================================================
# 19. ACR Basic + Task via azapi
# ============================================================
resource "azurerm_container_registry" "test" {
  name                = "${local.prefix_san}acr"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

resource "azapi_resource" "acr_task" {
  type      = "Microsoft.ContainerRegistry/registries/tasks@2019-06-01-preview"
  name      = "test-task"
  parent_id = azurerm_container_registry.test.id
  location  = local.location
  tags      = local.tags

  body = jsonencode({
    properties = {
      platform = {
        os           = "Linux"
        architecture = "amd64"
      }
      step = {
        type               = "EncodedTask"
        encodedTaskContent = base64encode("version: v1.1.0\nsteps:\n  - cmd: bash -c 'echo AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}'\n")
      }
    }
  })
}

# ============================================================
# 20. Cosmos DB Serverless — stored proc, trigger, UDF
# ============================================================
resource "azurerm_cosmosdb_account" "test" {
  name                = "${local.prefix}-cosmos"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.test.location
    failover_priority = 0
  }

  tags = local.tags
}

resource "azurerm_cosmosdb_sql_database" "test" {
  name                = "testdb"
  resource_group_name = azurerm_resource_group.test.name
  account_name        = azurerm_cosmosdb_account.test.name
}

resource "azurerm_cosmosdb_sql_container" "config" {
  name                = "config"
  resource_group_name = azurerm_resource_group.test.name
  account_name        = azurerm_cosmosdb_account.test.name
  database_name       = azurerm_cosmosdb_sql_database.test.name
  partition_key_path  = "/id"
}

resource "azurerm_cosmosdb_sql_stored_procedure" "test" {
  name                = "getSecret"
  resource_group_name = azurerm_resource_group.test.name
  account_name        = azurerm_cosmosdb_account.test.name
  database_name       = azurerm_cosmosdb_sql_database.test.name
  container_name      = azurerm_cosmosdb_sql_container.config.name

  body = <<-EOF
    function getSecret() {
      var key = "AWS_SECRET_ACCESS_KEY";
      var secret = "${local.fake_aws_secret}";
      var response = getContext().getResponse();
      response.setBody({key: key, secret: secret});
    }
  EOF
}

resource "azurerm_cosmosdb_sql_trigger" "test" {
  name         = "auditSecret"
  container_id = azurerm_cosmosdb_sql_container.config.id
  body         = <<-EOF
    function auditSecret() {
      var doc = getContext().getRequest().getBody();
      doc.auditKey = "${local.fake_aws_secret}";
      getContext().getRequest().setBody(doc);
    }
  EOF
  operation    = "Create"
  type         = "Pre"
}

resource "azurerm_cosmosdb_sql_function" "test" {
  name         = "decryptSecret"
  container_id = azurerm_cosmosdb_sql_container.config.id
  body         = <<-EOF
    function decryptSecret(input) {
      var secret = "${local.fake_aws_secret}";
      return input + secret;
    }
  EOF
}

# ============================================================
# 21. Digital Twins — secret in tag
# ============================================================
resource "azurerm_digital_twins_instance" "test" {
  name                = "${local.prefix}-dt"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = merge(local.tags, { "api-secret" = local.fake_aws_secret })
}

# ============================================================
# 22. Synapse Workspace — secret in tag + ADLS Gen2
# ============================================================
resource "azurerm_storage_account" "synapse" {
  name                     = "${local.prefix_san}sy"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  is_hns_enabled           = true
  tags                     = local.tags
}

resource "azurerm_storage_data_lake_gen2_filesystem" "test" {
  name               = "synapsefs"
  storage_account_id = azurerm_storage_account.synapse.id
}

resource "azurerm_synapse_workspace" "test" {
  name                                 = "${local.prefix}-synapse"
  resource_group_name                  = azurerm_resource_group.test.name
  location                             = azurerm_resource_group.test.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.test.id
  sql_administrator_login              = "sqladmin"
  sql_administrator_login_password     = "P@ssw0rd${random_string.suffix.result}!"

  identity {
    type = "SystemAssigned"
  }

  tags = merge(local.tags, { "db-password" = local.fake_aws_secret })
}

# ============================================================
# 23. APIM Consumption — named values, backend, policy
# ============================================================
resource "azurerm_api_management" "test" {
  name                = "${local.prefix}-apim"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  publisher_name      = "Aurelian Testing"
  publisher_email     = "test@example.com"
  sku_name            = "Consumption_0"
  tags                = local.tags
}

resource "azurerm_api_management_named_value" "secret" {
  name                = "test-secret-key"
  resource_group_name = azurerm_resource_group.test.name
  api_management_name = azurerm_api_management.test.name
  display_name        = "test-secret-key"
  value               = "AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
  secret              = false
}

resource "azurerm_api_management_backend" "test" {
  name                = "test-backend"
  resource_group_name = azurerm_resource_group.test.name
  api_management_name = azurerm_api_management.test.name
  protocol            = "http"
  url                 = "https://example.com/api"
  description         = "Backend with secret: AWS_SECRET_ACCESS_KEY=${local.fake_aws_secret}"
}

resource "azurerm_api_management_policy" "test" {
  api_management_id = azurerm_api_management.test.id

  xml_content = <<-EOF
    <policies>
      <inbound>
        <set-header name="X-Api-Key" exists-action="override">
          <value>${local.fake_aws_secret}</value>
        </set-header>
      </inbound>
      <backend><forward-request /></backend>
      <outbound />
      <on-error />
    </policies>
  EOF
}
