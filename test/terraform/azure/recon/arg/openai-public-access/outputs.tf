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
      openai_public = azurerm_cognitive_account.openai_public.name
    }

    private_resources = merge(
      {
        openai_private_disabled = azurerm_cognitive_account.openai_private_disabled.name
      },
      var.enable_private_endpoint ? {
        openai_with_pe = azurerm_cognitive_account.openai_with_pe[0].name
      } : {},
      {
        text_analytics_public  = azurerm_cognitive_account.text_analytics_public.name
        form_recognizer_public = azurerm_cognitive_account.form_recognizer_public.name
      }
    )

    expected_detections     = 1
    expected_non_detections = var.enable_private_endpoint ? 4 : 3
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA OPENAI PUBLIC ACCESS TESTING
    ============================================

    Template: openai_public_access
    Resource Group: ${azurerm_resource_group.main.name}

    Test Resources:
      TP: ${azurerm_cognitive_account.openai_public.name} (OpenAI, public, no PE) -> SHOULD DETECT
      TN: ${azurerm_cognitive_account.openai_private_disabled.name} (OpenAI, access disabled) -> SHOULD NOT DETECT
      ${var.enable_private_endpoint ? "TN: ${azurerm_cognitive_account.openai_with_pe[0].name} (OpenAI, public + PE) -> SHOULD NOT DETECT" : "TN: [skipped - enable_private_endpoint=false]"}
      FP: ${azurerm_cognitive_account.text_analytics_public.name} (TextAnalytics, not OpenAI) -> SHOULD NOT DETECT
      FP: ${azurerm_cognitive_account.form_recognizer_public.name} (FormRecognizer, not OpenAI) -> SHOULD NOT DETECT

    Run Nebula scan:
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t openai_public_access \
        -o /tmp/nebula-openai-scan/

    Validate:
      # Should find 1 resource (openai_public only)
      cat /tmp/nebula-openai-scan/*.json | jq '.findings | length'

      # Should NOT find any private/non-OpenAI resources
      cat /tmp/nebula-openai-scan/*.json | jq '.findings[] | select(.name | contains("prv") or contains("ta-") or contains("fr-"))'

    Cleanup:
      terraform destroy -auto-approve
  EOT
}
