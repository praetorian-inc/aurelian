package output

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

// BillingAccountInfo holds metadata about a GCP billing account.
type BillingAccountInfo struct {
	Name            string `json:"name"`                        // e.g. "billingAccounts/012345-ABCDEF-678901"
	DisplayName     string `json:"display_name"`
	Open            bool   `json:"open"`
	MasterAccountID string `json:"master_account_id,omitempty"`
}

// ProjectBinding maps a project to its billing account.
type ProjectBinding struct {
	ProjectID        string `json:"project_id"`
	BillingAccountID string `json:"billing_account_id"`
	BillingEnabled   bool   `json:"billing_enabled"`
}

// GCPBillingSummary holds billing account metadata and project-to-billing mappings.
type GCPBillingSummary struct {
	model.BaseAurelianModel
	BillingAccounts []BillingAccountInfo `json:"billing_accounts"`
	ProjectBindings []ProjectBinding     `json:"project_bindings"`
}

// String renders the billing summary as a formatted markdown table.
func (b *GCPBillingSummary) String() string {
	var sb strings.Builder

	// Billing Accounts table.
	sb.WriteString("\nGCP Billing Accounts:\n\n")
	if len(b.BillingAccounts) == 0 {
		sb.WriteString("(none)\n")
	} else {
		acctHeaders := []string{"Name", "Display Name", "Open", "Master Account"}
		acctRows := make([][]string, 0, len(b.BillingAccounts))
		for _, acct := range b.BillingAccounts {
			openStr := "no"
			if acct.Open {
				openStr = "yes"
			}
			master := acct.MasterAccountID
			if master == "" {
				master = "-"
			}
			acctRows = append(acctRows, []string{acct.Name, acct.DisplayName, openStr, master})
		}
		sb.WriteString(renderTable(acctHeaders, acctRows))
	}

	// Project Bindings table.
	sb.WriteString("\nProject Billing Bindings:\n\n")
	if len(b.ProjectBindings) == 0 {
		sb.WriteString("(none)\n")
	} else {
		projHeaders := []string{"Project ID", "Billing Account", "Billing Enabled"}
		projRows := make([][]string, 0, len(b.ProjectBindings))
		for _, proj := range b.ProjectBindings {
			enabledStr := "no"
			if proj.BillingEnabled {
				enabledStr = "yes"
			}
			projRows = append(projRows, []string{proj.ProjectID, proj.BillingAccountID, enabledStr})
		}
		sb.WriteString(renderTable(projHeaders, projRows))
	}

	return sb.String()
}

// renderTable renders a markdown-style table with the given headers and rows.
func renderTable(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	// Header row.
	for i, h := range headers {
		if i > 0 {
			sb.WriteString(" | ")
		}
		fmt.Fprintf(&sb, "%-*s", widths[i], h)
	}
	sb.WriteByte('\n')

	// Separator row.
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("-|-")
		}
		sb.WriteString(strings.Repeat("-", w))
	}
	sb.WriteByte('\n')

	// Data rows.
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				sb.WriteString(" | ")
			}
			if i < len(widths) {
				fmt.Fprintf(&sb, "%-*s", widths[i], cell)
			} else {
				sb.WriteString(cell)
			}
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}
