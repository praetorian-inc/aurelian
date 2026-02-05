package azure
import (
	"context"
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"path/filepath"
)
type AzureRoleAssignmentsOutputFormatterLink struct {
	*base.NativeAzureLink
}
func NewAzureRoleAssignmentsOutputFormatterLink(args map[string]any) *AzureRoleAssignmentsOutputFormatterLink {
	return &AzureRoleAssignmentsOutputFormatterLink{
		NativeAzureLink: base.NewNativeAzureLink("role-assignments-output-formatter", args),
	}
}
func (l *AzureRoleAssignmentsOutputFormatterLink) Process(ctx context.Context, input any) ([]any, error) {
	assignments, ok := input.([]*types.RoleAssignmentDetails)
	if !ok {
		return nil, fmt.Errorf("expected []*types.RoleAssignmentDetails input, got %T", input)
	}
	if len(assignments) == 0 {
		return l.Outputs(), nil
	}
	// Get output directory
	outputDir := l.ArgString("output", "")
	// Generate base filename - use subscription ID only, no timestamp
	baseFilename := fmt.Sprintf("role-assignments-%s", assignments[0].SubscriptionID)
	// Create full paths
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
	mdFilePath := filepath.Join(outputDir, baseFilename+".md")
	// Send JSON output using NamedOutputData
	jsonOutputData := outputters.NewNamedOutputData(assignments, jsonFilePath)
	l.Send(jsonOutputData)
	// Create markdown table for both console and file output
	table := &AzureRoleAssignmentsTable{
		TableHeading: fmt.Sprintf("Azure Role Assignments\nSubscription: %s (%s)",
			assignments[0].SubscriptionName,
			assignments[0].SubscriptionID),
		Headers: []string{
			"Principal Type",
			"Principal ID", 
			"Role Name",
			"Scope Type",
			"Scope Name",
		},
		Rows:         make([][]string, 0, len(assignments)),
		assignments:  assignments, // Store for console output
	}
	// Add rows for each assignment
	for _, assignment := range assignments {
		roleName := assignment.RoleDisplayName
		if roleName == "" {
			roleName = assignment.RoleDefinitionID
		}
		table.Rows = append(table.Rows, []string{
			assignment.PrincipalType,
			assignment.PrincipalID,
			roleName,
			assignment.ScopeType,
			assignment.ScopeDisplayName,
		})
	}
	// Send markdown table for console output (Markdownable interface)
	l.Send(table)
	// Send markdown file output
	markdownTable := types.MarkdownTable{
		TableHeading: table.TableHeading,
		Headers:      table.Headers,
		Rows:         table.Rows,
	}
	mdOutputData := outputters.NewNamedOutputData(markdownTable, mdFilePath)
	l.Send(mdOutputData)
	return l.Outputs(), nil
}
func (l *AzureRoleAssignmentsOutputFormatterLink) Parameters() []plugin.Parameter {
	return options.AzureReconBaseOptions()
}
// AzureRoleAssignmentsTable implements the Markdownable interface for console output
type AzureRoleAssignmentsTable struct {
	TableHeading string
	Headers      []string
	Rows         [][]string
	assignments  []*types.RoleAssignmentDetails
}
func (t *AzureRoleAssignmentsTable) Values() []any {
	// Print console table format immediately
	fmt.Printf("\n%s\n", t.TableHeading)
	fmt.Printf("| %-15s | %-36s | %-30s | %-15s | %-30s |\n", 
		t.Headers[0], t.Headers[1], t.Headers[2], t.Headers[3], t.Headers[4])
	fmt.Printf("|%s|%s|%s|%s|%s|\n", 
		"----------------", "-------------------------------------", "-------------------------------", "----------------", "-------------------------------")
	for _, row := range t.Rows {
		fmt.Printf("| %-15s | %-36s | %-30s | %-15s | %-30s |\n", 
			truncate(row[0], 15), truncate(row[1], 36), truncate(row[2], 30), 
			truncate(row[3], 15), truncate(row[4], 30))
	}
	fmt.Printf("\nTotal role assignments: %d\n", len(t.Rows))
	return []any{} // Console output handled directly
}
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
