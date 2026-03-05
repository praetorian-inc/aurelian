output "resource_group_name" {
  description = "Name of the resource group containing all test resources"
  value       = azurerm_resource_group.main.name
}

output "test_summary" {
  description = "Summary of deployed resources and expected detection results"
  value = {
    resource_group = azurerm_resource_group.main.name
    location       = azurerm_resource_group.main.location

    kql_tests = {
      tp_public_no_restrictions = var.enable_tp ? azurerm_windows_function_app.public_no_restrictions[0].name : "disabled"
      tn_private                = var.enable_tn_private ? azurerm_windows_function_app.private[0].name : "disabled"
    }

    enricher_tests = {
      tp_ip_restricted     = var.enable_tn_restricted ? azurerm_windows_function_app.public_ip_restricted[0].name : "disabled"
      tp_with_slot         = var.enable_tp_slot ? azurerm_windows_function_app.with_slot[0].name : "disabled"
      tp_slot_staging      = var.enable_tp_slot ? azurerm_windows_function_app_slot.staging[0].name : "disabled"
      tn_easyauth          = var.enable_tn_easyauth ? azurerm_windows_function_app.easyauth[0].name : "disabled"
      tp_anonymous_trigger = var.enable_tp_anonymous ? azurerm_windows_function_app.anonymous_trigger[0].name : "disabled"
      tn_keyed_trigger     = var.enable_tn_keyed ? azurerm_windows_function_app.keyed_trigger[0].name : "disabled"
    }

    expected_kql_detections     = (var.enable_tp ? 1 : 0)
    expected_kql_non_detections = (var.enable_tn_private ? 1 : 0)

    note = "ARG does NOT index siteConfig.ipSecurityRestrictions, so IP-restricted apps are detected by KQL. The enricher checks IP restrictions via Management API and reports them as compensating controls. All enricher test apps (slot, easyauth, ip-restricted, anonymous, keyed) are detected by KQL since they're public."
  }
}

output "test_commands" {
  description = "Commands to test Nebula detection after deployment"
  value       = <<-EOT
    ============================================
    NEBULA FUNCTION APPS PUBLIC HTTP TRIGGERS
    COMPREHENSIVE TESTING (KQL + Enricher)
    ============================================

    Template: function_apps_public_http_triggers
    Resource Group: ${azurerm_resource_group.main.name}

    ── KQL Filter Tests ──
    TP:  "${var.enable_tp ? azurerm_windows_function_app.public_no_restrictions[0].name : "disabled"}" (public, no IP restrictions)
    TN:  "${var.enable_tn_private ? azurerm_windows_function_app.private[0].name : "disabled"}" (public access disabled)

    ── Enricher Tests (all detected by KQL — enricher adds context) ──
    TP-IPR:      "${var.enable_tn_restricted ? azurerm_windows_function_app.public_ip_restricted[0].name : "disabled"}" (enricher notes IP restrictions)
    TP-SLOT:     "${var.enable_tp_slot ? azurerm_windows_function_app.with_slot[0].name : "disabled"}" + staging slot
    TN-EASYAUTH: "${var.enable_tn_easyauth ? azurerm_windows_function_app.easyauth[0].name : "disabled"}" (EasyAuth enabled)
    TP-ANON:     "${var.enable_tp_anonymous ? azurerm_windows_function_app.anonymous_trigger[0].name : "disabled"}" (needs func deploy)
    TN-KEYED:    "${var.enable_tn_keyed ? azurerm_windows_function_app.keyed_trigger[0].name : "disabled"}" (needs func deploy)

    ── Step 1: Run Nebula scan ──
      go run . azure recon arg-scan \
        -s ${data.azurerm_client_config.current.subscription_id} \
        -t /tmp/nebula-single-template \
        -o /tmp/nebula-func-http-triggers-scan/

    ── Step 2: Validate KQL results ──
    Expected KQL detections: 6 (all public apps — ARG can't filter on IP restrictions)
    Expected KQL non-detections: 1 (private app only)

    ── Step 3: Validate enricher output ──
    Check enricher commands in scan output for:
    - TP-IPR: "IP restrictions found: 1 rule(s)" in output
    - TP-SLOT: "Deployment slots found: 1 (staging)" in output
    - TN-EASYAUTH: "EasyAuth is ENABLED" in output
    - TP-ANON: After func deploy, "anonymous" auth level in trigger list
    - TN-KEYED: After func deploy, "function" auth level in trigger list

    ── Cleanup ──
      terraform destroy -auto-approve
  EOT
}
