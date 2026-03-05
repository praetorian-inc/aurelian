output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    public_resources = {
      domain_public_no_ip   = azurerm_eventgrid_domain.public_no_ip.name
      domain_public_with_ip = azurerm_eventgrid_domain.public_with_ip.name
    }

    private_resources = {
      domain_private   = azurerm_eventgrid_domain.private.name
      topic_not_domain = azurerm_eventgrid_topic.public.name
    }

    expected_detections     = 2
    expected_non_detections = 2
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA EVENT GRID PUBLIC ACCESS TESTING
    ============================================

    Template: event_grid_domain_public
    Resource Group: ${azurerm_resource_group.main.name}

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t event_grid_domain_public \
        -o /tmp/nebula-eventgrid-scan/

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
