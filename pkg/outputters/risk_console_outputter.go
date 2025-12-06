package outputters

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type RiskConsoleOutputter struct {
	*chain.BaseOutputter
	riskGroups map[string][]model.Risk // Map to store risks grouped by name
}

// RiskInstance represents a single instance of a risk
type RiskInstance struct {
	Resource string
	IP       string
	Proof    map[string]any
}

// NewRiskConsoleOutputter creates a new console outputter for Risk types
func NewRiskConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &RiskConsoleOutputter{
		riskGroups: make(map[string][]model.Risk),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects risk items for grouped output
func (o *RiskConsoleOutputter) Output(v any) error {
	// Try to get a Janus Risk type
	janusRisk, ok := v.(model.Risk)
	if !ok {
		// Try as pointer
		janusRiskPtr, ok := v.(*model.Risk)
		if !ok {
			return nil // Not a Janus Risk, silently ignore
		}
		janusRisk = *janusRiskPtr
	}

	// Store the risk in the appropriate group
	o.riskGroups[janusRisk.Name] = append(o.riskGroups[janusRisk.Name], janusRisk)

	return nil
}

// Initialize is called when the outputter is initialized
func (o *RiskConsoleOutputter) Initialize() error {
	return nil
}

// Complete is called when the chain is complete - display all collected risks
func (o *RiskConsoleOutputter) Complete() error {
	if len(o.riskGroups) == 0 {
		message.Info("No security risks found")
		return nil
	}

	// Display summary first
	totalRisks := 0
	for _, risks := range o.riskGroups {
		totalRisks += len(risks)
	}

	message.Section("=== Security Risk Summary ===")
	message.Info("Found %d security risks across %d categories", totalRisks, len(o.riskGroups))

	// Display each risk group
	for riskName, risks := range o.riskGroups {
		o.displayRiskGroup(riskName, risks)
	}

	return nil
}

// displayRiskGroup formats and displays a group of risks with the same name
func (o *RiskConsoleOutputter) displayRiskGroup(riskName string, risks []model.Risk) {
	if len(risks) == 0 {
		return
	}

	// Use the first risk for common properties
	firstRisk := risks[0]
	severity := o.formatSeverity(firstRisk.Severity())

	message.Section("%s %s (%d %s)",
		severity,
		strings.ToUpper(riskName),
		len(risks),
		o.pluralize("instance", len(risks)))

	// Show impact once for the group
	o.displayGroupImpact(firstRisk)

	// Display each instance path
	for i, risk := range risks {
		o.displayRiskPath(risk, i+1, len(risks))
	}
}

// displayGroupImpact shows the impact description once for the entire risk group
func (o *RiskConsoleOutputter) displayGroupImpact(risk model.Risk) {
	// Look for common privilege escalation patterns in the risk name
	switch {
	case strings.Contains(strings.ToLower(risk.Name), "createaccesskey"):
		message.Info("  Impact: Can authenticate as other users with potentially higher privileges")
	case strings.Contains(strings.ToLower(risk.Name), "login profile"):
		message.Info("  Impact: Can set/reset console passwords for other users")
	case strings.Contains(strings.ToLower(risk.Name), "policy manipulation"):
		message.Info("  Impact: Can modify trust relationships or create elevated policy versions")
	case strings.Contains(strings.ToLower(risk.Name), "lambda"):
		if strings.Contains(strings.ToLower(risk.Name), "updatefunctioncode") {
			message.Info("  Impact: Can modify Lambda function code to execute with elevated privileges")
		} else {
			message.Info("  Impact: Can create Lambda functions with elevated execution roles")
		}
	case strings.Contains(strings.ToLower(risk.Name), "cloudformation"):
		message.Info("  Impact: Can deploy infrastructure with elevated permissions via CloudFormation")
	case strings.Contains(strings.ToLower(risk.Name), "multi-hop"):
		message.Info("  Impact: Multi-step privilege escalation chain leading to administrative access")
	default:
		message.Info("  Impact: %s", risk.Name)
	}
}

// displayRiskPath shows the actual attack path from proof data
func (o *RiskConsoleOutputter) displayRiskPath(risk model.Risk, instanceNum, totalInstances int) {
	// For now, use simple DNS-based display since we can't easily access proof file content in this context
	// The proper solution would be to either:
	// 1. Store the original permission in the risk somewhere, or  
	// 2. Parse the proof file content (which contains record.String() output)
	pathDisplay := o.buildPathFromRisk(risk)
	if pathDisplay != "" {
		message.Success("%s", pathDisplay)
		return
	}

	// Fallback: try parsing comment (for backward compatibility)
	pathDisplay = o.parseCommentForPath(risk.Comment)
	if pathDisplay != "" {
		message.Success("%s", pathDisplay)
	} else {
		// Final fallback display
		message.Success("Instance %d/%d - Principal: %s", instanceNum, totalInstances, o.extractPrincipalName(risk.DNS))
	}
}

// parseCommentForPath extracts attack path components from the formatted comment
func (o *RiskConsoleOutputter) parseCommentForPath(comment string) string {
	if comment == "" {
		return ""
	}

	// Parse comment format: "Attacker: name | Target: name | Permission: permission"
	// or "Attacker: name | Target: function | Execution Role: role | Permission1: perm1 | Permission2: perm2"

	parts := strings.Split(comment, " | ")
	components := make(map[string]string)

	for _, part := range parts {
		if colonIndex := strings.Index(part, ": "); colonIndex > 0 {
			key := part[:colonIndex]
			value := part[colonIndex+2:]
			components[key] = value
		}
	}

	// Build path based on available components
	attacker := components["Attacker"]
	target := components["Target"]
	executionRole := components["Execution Role"]
	permission := components["Permission"]
	permission1 := components["Permission1"]
	permission2 := components["Permission2"]

	if attacker != "" && executionRole != "" && permission1 != "" && permission2 != "" {
		// Lambda multi-hop path with explicit permissions
		return fmt.Sprintf("(%s)-[:%s]->(%s)-[:%s]->(%s)", attacker, permission1, target, permission2, executionRole)
	} else if attacker != "" && executionRole != "" {
		// Lambda path: attacker -> function -> execution role
		// We need to infer the function name from the context, but for now show a simplified path
		return fmt.Sprintf("(%s)-[:lambda:UpdateFunctionCode]->(function)-[:sts:AssumeRole]->(%s)", attacker, executionRole)
	} else if attacker != "" && target != "" && permission != "" {
		// Simple two-node path
		return fmt.Sprintf("(%s)-[:%s]->(%s)", attacker, permission, target)
	}

	return ""
}

// buildPathFromRisk constructs attack path display from risk DNS pattern
func (o *RiskConsoleOutputter) buildPathFromRisk(risk model.Risk) string {
	// Parse DNS pattern: target.Name:risk-name:source.Name
	parts := strings.Split(risk.DNS, ":")
	if len(parts) >= 3 {
		targetName := parts[0]
		sourceName := parts[2]
		riskName := parts[1]
		
		// Use the risk name directly as a readable label instead of trying to reconstruct permission
		// Convert hyphens to spaces for readability
		label := strings.ReplaceAll(riskName, "-", " ")
		label = strings.Title(label)
		
		return fmt.Sprintf("(%s)-[:%s]->(%s)", sourceName, label, targetName)
	}
	
	return ""
}

func (o *RiskConsoleOutputter) buildSimplePathDisplay(nodes []map[string]any, relationships []map[string]any) string {
	if len(nodes) < 2 || len(relationships) < 1 {
		return ""
	}

	// Extract node names
	var attackerName, targetName, permission string

	for _, node := range nodes {
		nodeType, _ := node["type"].(string)
		name, _ := node["name"].(string)

		switch nodeType {
		case "attacker":
			attackerName = name
		case "target":
			targetName = name
		}
	}

	// Extract permission
	if len(relationships) > 0 {
		permission, _ = relationships[0]["permission"].(string)
	}

	if attackerName != "" && targetName != "" && permission != "" {
		return fmt.Sprintf("(%s)-[:%s]->(%s)", attackerName, permission, targetName)
	}

	return ""
}

func (o *RiskConsoleOutputter) buildLambdaPathDisplay(nodes []map[string]any, relationships []map[string]any) string {
	if len(nodes) < 2 {
		return ""
	}

	// Extract node names by type
	var attackerName, functionName, executionRoleName string

	for _, node := range nodes {
		nodeType, _ := node["type"].(string)
		name, _ := node["name"].(string)

		switch nodeType {
		case "attacker":
			attackerName = name
		case "function":
			functionName = name
		case "execution_role":
			executionRoleName = name
		}
	}

	// Extract permissions
	var permission1, permission2 string
	if len(relationships) >= 1 {
		permission1, _ = relationships[0]["permission"].(string)
	}
	if len(relationships) >= 2 {
		permission2, _ = relationships[1]["permission"].(string)
	}

	// Build path display based on available components
	if attackerName != "" && executionRoleName != "" {
		if functionName != "" && permission1 != "" && permission2 != "" {
			// Full Lambda path with function
			return fmt.Sprintf("(%s)-[:%s]->(%s)-[:%s]->(%s)",
				attackerName, permission1, functionName, permission2, executionRoleName)
		} else {
			// Simplified Lambda path
			return fmt.Sprintf("(%s)-[:lambda:UpdateFunctionCode]->(function)-[:sts:AssumeRole]->(%s)",
				attackerName, executionRoleName)
		}
	}

	return ""
}

func (o *RiskConsoleOutputter) buildCloudFormationPathDisplay(nodes []map[string]any, relationships []map[string]any) string {
	// Use simple path display for CloudFormation paths
	return o.buildSimplePathDisplay(nodes, relationships)
}

func (o *RiskConsoleOutputter) buildMultiHopPathDisplay(nodes []map[string]any, relationships []map[string]any) string {
	if len(nodes) >= 2 {
		// For multi-hop, show simplified representation
		var attackerName, targetName string

		for _, node := range nodes {
			nodeType, _ := node["type"].(string)
			name, _ := node["name"].(string)

			switch nodeType {
			case "attacker":
				attackerName = name
			case "target":
				targetName = name
			}
		}

		if attackerName != "" && targetName != "" {
			return fmt.Sprintf("(%s)-[*2..3]->(%s)", attackerName, targetName)
		}
	}

	return ""
}

// buildPathFromQueryData constructs the attack path display from Neo4j query results
func (o *RiskConsoleOutputter) buildPathFromQueryData(data map[string]any) string {
	// Extract path components based on what's returned from the queries
	attacker := o.extractPrincipalNameFromData(data["attacker"])
	target := o.extractPrincipalNameFromData(data["target"])
	function := o.extractPrincipalNameFromData(data["function"])
	executionRole := o.extractPrincipalNameFromData(data["execution_role"])
	permission := o.extractStringFromData(data["permission"])
	permission1 := o.extractStringFromData(data["permission1"])
	permission2 := o.extractStringFromData(data["permission2"])

	// Build path based on available components
	if attacker != "" && target != "" && permission != "" {
		// Simple two-node path: (attacker)-[:permission]->(target)
		return fmt.Sprintf("(%s)-[:%s]->(%s)", attacker, permission, target)
	}

	if attacker != "" && function != "" && executionRole != "" && permission1 != "" && permission2 != "" {
		// Lambda path: (attacker)-[:permission1]->(function)-[:permission2]->(execution_role)
		funcName := o.extractFunctionName(function)
		roleName := o.extractRoleName(executionRole)
		return fmt.Sprintf("(%s)-[:%s]->(%s)-[:%s]->(%s)", attacker, permission1, funcName, permission2, roleName)
	}

	return ""
}

// Helper functions for extracting clean names from various data formats
func (o *RiskConsoleOutputter) extractPrincipalNameFromData(data any) string {
	if data == nil {
		return ""
	}

	switch d := data.(type) {
	case string:
		return o.extractPrincipalName(d)
	default:
		return ""
	}
}

func (o *RiskConsoleOutputter) extractStringFromData(data any) string {
	if data == nil {
		return ""
	}

	switch d := data.(type) {
	case string:
		return d
	default:
		return ""
	}
}

func (o *RiskConsoleOutputter) extractFunctionName(arn string) string {
	// Extract function name from Lambda ARN
	// Example: arn:aws:lambda:us-east-1:account:function:function-name
	if strings.Contains(arn, ":function:") {
		parts := strings.Split(arn, ":function:")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return o.extractPrincipalName(arn) // fallback
}

func (o *RiskConsoleOutputter) extractRoleName(arn string) string {
	// Extract role name from IAM role ARN
	// Example: arn:aws:iam::account:role/role-name
	return o.extractPrincipalName(arn)
}

func (o *RiskConsoleOutputter) displayRiskInstance(risk model.Risk, instanceNum, totalInstances int) {
	instanceHeader := fmt.Sprintf("Instance %d/%d - Principal: %s", instanceNum, totalInstances, o.extractPrincipalName(risk.DNS))

	switch risk.Severity() {
	case "H", "TH": // TriageHigh
		message.Success("%s", instanceHeader)
		o.displayAttackPath(risk)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	case "M", "TM": // TriageMedium
		message.Success("%s", instanceHeader)
		o.displayAttackPath(risk)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	case "L", "TL": // TriageLow
		message.Success("%s", instanceHeader)
		o.displayAttackPath(risk)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	default:
		message.Success("%s", instanceHeader)
		o.displayAttackPath(risk)
		if risk.Comment != "" {
			message.Info("  Details: %s", risk.Comment)
		}
		if risk.Source != "" {
			message.Info("  Source: %s", risk.Source)
		}
	}
}

// extractPrincipalName extracts the principal name from an ARN
func (o *RiskConsoleOutputter) extractPrincipalName(arn string) string {
	// Extract the last part of the ARN after the last /
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	// Fallback to extracting after the last :
	parts = strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return arn
}

// displayAttackPath shows the privilege escalation path in a readable format
func (o *RiskConsoleOutputter) displayAttackPath(risk model.Risk) {
	// Try to extract attack path information from the risk's raw data
	rawData := risk.Raw()

	// Parse the raw JSON to extract potential path information
	var riskData map[string]any
	if err := json.Unmarshal([]byte(rawData), &riskData); err != nil {
		return
	}

	// Look for common privilege escalation patterns in the risk name
	switch {
	case strings.Contains(strings.ToLower(risk.Name), "createaccesskey"):
		o.displayCreateAccessKeyPath(risk)
	case strings.Contains(strings.ToLower(risk.Name), "login profile"):
		o.displayLoginProfilePath(risk)
	case strings.Contains(strings.ToLower(risk.Name), "policy manipulation"):
		o.displayPolicyManipulationPath(risk)
	case strings.Contains(strings.ToLower(risk.Name), "lambda"):
		o.displayLambdaPath(risk)
	case strings.Contains(strings.ToLower(risk.Name), "cloudformation"):
		o.displayCloudFormationPath(risk)
	case strings.Contains(strings.ToLower(risk.Name), "multi-hop"):
		o.displayMultiHopPath(risk)
	default:
		message.Info("  Attack Vector: %s", risk.Name)
	}
}

// displayCreateAccessKeyPath shows CreateAccessKey privilege escalation
func (o *RiskConsoleOutputter) displayCreateAccessKeyPath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	message.Info("  Attack Path: (%s)-[:iam:CreateAccessKey]->(target_user)", attacker)
	message.Info("  Impact: Can authenticate as other users with potentially higher privileges")
}

// displayLoginProfilePath shows login profile manipulation
func (o *RiskConsoleOutputter) displayLoginProfilePath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	message.Info("  Attack Path: (%s)-[:iam:CreateLoginProfile|UpdateLoginProfile]->(target_user)", attacker)
	message.Info("  Impact: Can set/reset console passwords for other users")
}

// displayPolicyManipulationPath shows policy manipulation attacks
func (o *RiskConsoleOutputter) displayPolicyManipulationPath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	message.Info("  Attack Path: (%s)-[:iam:UpdateAssumeRolePolicy|CreatePolicyVersion]->(target)", attacker)
	message.Info("  Impact: Can modify trust relationships or create elevated policy versions")
}

// displayLambdaPath shows Lambda-based privilege escalation
func (o *RiskConsoleOutputter) displayLambdaPath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	if strings.Contains(strings.ToLower(risk.Name), "updatefunctioncode") {
		message.Info("  Attack Path: (%s)-[:lambda:UpdateFunctionCode]->(function)-[:sts:AssumeRole]->(privileged_role)", attacker)
		message.Info("    Impact: Can modify Lambda function code to execute with elevated privileges")
	} else {
		message.Info("  Attack Path: (%s)-[:lambda:CreateFunction + iam:PassRole]->(privileged_role)", attacker)
		message.Info("  Impact: Can create Lambda functions with elevated execution roles")
	}
}

// displayCloudFormationPath shows CloudFormation-based escalation
func (o *RiskConsoleOutputter) displayCloudFormationPath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	message.Info("  Attack Path: (%s)-[:cloudformation:CreateStack|UpdateStack + iam:PassRole]->(privileged_role)", attacker)
	message.Info("  Impact: Can deploy infrastructure with elevated permissions via CloudFormation")
}

// displayMultiHopPath shows complex multi-hop escalation chains
func (o *RiskConsoleOutputter) displayMultiHopPath(risk model.Risk) {
	attacker := o.extractPrincipalName(risk.DNS)
	message.Info("  Attack Path: (%s)-[*2..3]->(admin_principal)", attacker)
	message.Info("  Impact: Multi-step privilege escalation chain leading to administrative access")
}

func (o *RiskConsoleOutputter) formatSeverity(severity string) string {
	switch severity {
	case "H", "TH":
		return "🔴 HIGH"
	case "M", "TM":
		return "🟡 MEDIUM"
	case "L", "TL":
		return "🟢 LOW"
	default:
		return fmt.Sprintf("⚪ UNKNOWN (%s)", severity)
	}
}

func (o *RiskConsoleOutputter) pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

// Params returns the parameters for this outputter
func (o *RiskConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}
