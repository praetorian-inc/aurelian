package outputters

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/internal/message"
)

type NPFindingsConsoleOutputter struct {
	*chain.BaseOutputter
	findings []types.NPFinding
}

// NewNPFindingsConsoleOutputter creates a new console outputter for NPFinding types
func NewNPFindingsConsoleOutputter(configs ...cfg.Config) chain.Outputter {
	o := &NPFindingsConsoleOutputter{
		findings: make([]types.NPFinding, 0),
	}
	o.BaseOutputter = chain.NewBaseOutputter(o, configs...)
	return o
}

// Output collects NPFinding items for grouped output
func (o *NPFindingsConsoleOutputter) Output(v any) error {
	// Try to get an NPFinding type
	npFinding, ok := v.(types.NPFinding)
	if !ok {
		// Try as pointer
		npFindingPtr, ok := v.(*types.NPFinding)
		if !ok {
			return nil // Not an NPFinding, silently ignore
		}
		npFinding = *npFindingPtr
	}

	// Store the finding for later output
	o.findings = append(o.findings, npFinding)
	return nil
}

// Initialize is called when the outputter is initialized
func (o *NPFindingsConsoleOutputter) Initialize() error {
	return nil
}

// Complete is called when the chain is complete - display all collected findings
func (o *NPFindingsConsoleOutputter) Complete() error {
	if len(o.findings) == 0 {
		return nil
	}

	message.Section("Nosey Parker Findings")

	// Group findings by rule name for better organization
	findingsByRule := make(map[string][]types.NPFinding)
	for _, finding := range o.findings {
		findingsByRule[finding.RuleName] = append(findingsByRule[finding.RuleName], finding)
	}

	// Output each group
	for ruleName, findings := range findingsByRule {
		message.Success("Rule: %s (%d findings)", message.Emphasize(ruleName), len(findings))

		for i, finding := range findings {
			o.outputFinding(finding, i+1, len(findings))
		}

		// Add some spacing between rule groups
		fmt.Println()
	}

	message.Info("Total findings: %d across %d rules", len(o.findings), len(findingsByRule))
	return nil
}

// outputFinding formats and displays a single NPFinding
func (o *NPFindingsConsoleOutputter) outputFinding(finding types.NPFinding, index, total int) {
	// Format the finding header
	message.Success("  [%d/%d] Finding ID: %s", index, total, finding.FindingID)

	// Output provenance information if available
	if finding.Provenance.Platform != "" || finding.Provenance.ResourceID != "" {
		var provenanceDetails []string

		if finding.Provenance.Platform != "" {
			provenanceDetails = append(provenanceDetails, fmt.Sprintf("Platform: %s", finding.Provenance.Platform))
		}
		if finding.Provenance.ResourceType != "" {
			provenanceDetails = append(provenanceDetails, fmt.Sprintf("Type: %s", finding.Provenance.ResourceType))
		}
		if finding.Provenance.ResourceID != "" {
			provenanceDetails = append(provenanceDetails, fmt.Sprintf("Resource: %s", finding.Provenance.ResourceID))
		}
		if finding.Provenance.RepoPath != "" {
			provenanceDetails = append(provenanceDetails, fmt.Sprintf("Repository: %s", finding.Provenance.RepoPath))
		}

		if len(provenanceDetails) > 0 {
			message.Info("    Location: %s", strings.Join(provenanceDetails, " | "))
		}
	}

	// Output the snippet with context
	if finding.Snippet.Before != "" || finding.Snippet.Matching != "" || finding.Snippet.After != "" {
		message.Info("    Context:")

		// Format the snippet with before/after context
		if finding.Snippet.Before != "" {
			// Show only last 50 chars of before context to keep it readable
			before := finding.Snippet.Before
			if len(before) > 50 {
				before = "..." + before[len(before)-47:]
			}
			fmt.Printf("      %s", strings.ReplaceAll(before, "\n", "\\n"))
		}

		// Highlight the matching text
		if finding.Snippet.Matching != "" {
			fmt.Printf("%s", message.Emphasize(finding.Snippet.Matching))
		}

		if finding.Snippet.After != "" {
			// Show only first 50 chars of after context
			after := finding.Snippet.After
			if len(after) > 50 {
				after = after[:47] + "..."
			}
			fmt.Printf("%s", strings.ReplaceAll(after, "\n", "\\n"))
		}

		fmt.Println() // New line after snippet
	}

	// Add git commit information if available
	if finding.Provenance.FirstCommit != nil {
		commit := finding.Provenance.FirstCommit.CommitMetadata
		if commit.CommitID != "" {
			message.Info("    First seen in commit: %s", commit.CommitID[:8])
			if commit.AuthorName != "" || commit.CommitterName != "" {
				author := commit.AuthorName
				if author == "" {
					author = commit.CommitterName
				}
				message.Info("    Author: %s", author)
			}
			if commit.Message != "" {
				// Truncate long commit messages
				commitMsg := commit.Message
				if len(commitMsg) > 100 {
					commitMsg = commitMsg[:97] + "..."
				}
				message.Info("    Message: %s", strings.TrimSpace(commitMsg))
			}
		}
	}

	// Add some spacing between findings
	if index < total {
		fmt.Println()
	}
}

// Params returns the parameters for this outputter
func (o *NPFindingsConsoleOutputter) Params() []cfg.Param {
	return []cfg.Param{}
}
