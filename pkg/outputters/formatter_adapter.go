package outputters

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// FormatterAdapter bridges Janus Outputter interface with new Formatter.
// It converts domain types (Risk, SecretFinding, CloudResource) to Finding
// before delegating to the wrapped Formatter.
type FormatterAdapter struct {
	*chain.BaseOutputter
	formatter      formatter.Formatter
	ctx            context.Context
	summary        formatter.Summary
	writer         io.Writer
	rawOutputWritten bool
}

// NewFormatterAdapter creates an adapter wrapping the given formatter.
// The writer parameter allows formatRaw to write directly to the output for raw JSON.
func NewFormatterAdapter(f formatter.Formatter, w io.Writer) *FormatterAdapter {
	if w == nil {
		w = os.Stdout
	}
	a := &FormatterAdapter{
		formatter: f,
		ctx:       context.Background(),
		writer:    w,
	}
	a.BaseOutputter = chain.NewBaseOutputter(a)
	return a
}

// NewFormatterAdapterConstructor returns an OutputterConstructor that creates
// FormatterAdapter instances with the specified format and optional writer.
// If no writer is provided, defaults to os.Stdout.
func NewFormatterAdapterConstructor(formatStr string, writers ...io.Writer) chain.OutputterConstructor {
	return func(configs ...cfg.Config) chain.Outputter {
		// Use provided writer or default to stdout
		var writer io.Writer = os.Stdout
		if len(writers) > 0 && writers[0] != nil {
			writer = writers[0]
		}
		format := formatter.Format(formatStr)

		// Create formatter with specified format
		f, err := formatter.New(formatter.Config{
			Format: format,
			Writer: writer,
		})
		if err != nil {
			// If formatter creation fails, return adapter with nil formatter
			// The adapter will handle this gracefully in Initialize()
			return NewFormatterAdapter(nil, writer)
		}

		return NewFormatterAdapter(f, writer)
	}
}

// Initialize prepares the formatter.
func (a *FormatterAdapter) Initialize() error {
	info := formatter.ToolInfo{
		Name:    "aurelian",
		Version: "1.0.0",
	}
	return a.formatter.Initialize(a.ctx, info)
}

// Output converts domain types to Finding and delegates to formatter.
func (a *FormatterAdapter) Output(val any) error {
	// Check for RawOutput marker FIRST
	if raw, ok := val.(RawOutput); ok {
		return a.formatRaw(raw.Data)
	}

	finding := a.convertToFinding(val)
	if finding.ID == "" {
		// Skip items that couldn't be converted
		return nil
	}

	// Track summary
	a.updateSummary(finding)

	return a.formatter.Format(a.ctx, finding)
}

// Complete finalizes the formatter output.
// If raw output was written via formatRaw(), this is a no-op to avoid double output.
func (a *FormatterAdapter) Complete() error {
	// If we wrote raw output directly, skip the formatter's Complete()
	// to avoid writing an additional JSON array
	if a.rawOutputWritten {
		return nil
	}
	return a.formatter.Complete(a.ctx, a.summary)
}

// formatRaw outputs the value directly as JSON without Finding conversion.
// Used for RawOutput marker types or explicit passthrough scenarios.
// Bypasses the Formatter entirely and writes raw JSON directly to the configured writer.
func (a *FormatterAdapter) formatRaw(val any) error {
	// Mark that we've written raw output so Complete() can skip formatter.Complete()
	a.rawOutputWritten = true

	// Write raw JSON directly to the writer, wrapped in an array to match Nebula-style output
	// This bypasses the Formatter's Finding-based structure
	encoder := json.NewEncoder(a.writer)
	encoder.SetIndent("", "  ")

	// Wrap in array to match expected JSON array output format
	return encoder.Encode([]any{val})
}

// Params returns empty params (adapter has no config params).
func (a *FormatterAdapter) Params() []cfg.Param {
	return []cfg.Param{}
}

// convertToFinding converts various domain types to Finding.
func (a *FormatterAdapter) convertToFinding(val any) formatter.Finding {
	switch v := val.(type) {
	case *output.Risk:
		if v.Target != nil {
			return a.fromCloudRisk(v.Target, v)
		}
		// Risk without target - create minimal finding
		return formatter.Finding{
			ID:          v.Name,
			RuleID:      v.Name,
			Severity:    a.mapSeverity(v.Status),
			Title:       v.Name,
			Description: v.Description,
			Source:      v.Source,
			Timestamp:   time.Now(),
		}

	case output.Risk:
		return a.convertToFinding(&v)

	case *output.SecretFinding:
		return a.fromSecretFinding(v)

	case output.SecretFinding:
		return a.convertToFinding(&v)

	case *output.CloudResource:
		return formatter.Finding{
			ID:     v.ResourceID,
			Title:  v.DisplayName,
			Source: "aurelian",
			Location: formatter.Location{
				ResourceARN:  v.ResourceID,
				ResourceType: v.ResourceType,
				Region:       v.Region,
				AccountID:    v.AccountRef,
			},
			Raw: v,
		}

	case output.CloudResource:
		return a.convertToFinding(&v)

	default:
		// Unknown type - wrap as raw
		return formatter.Finding{
			ID:     "unknown",
			Title:  "Unknown finding type",
			Source: "aurelian",
			Raw:    v,
		}
	}
}

// mapSeverity converts Risk.Status to Severity.
func (a *FormatterAdapter) mapSeverity(status string) formatter.Severity {
	if len(status) < 2 {
		return formatter.SeverityInfo
	}
	switch status[1] {
	case 'C':
		return formatter.SeverityCritical
	case 'H':
		return formatter.SeverityHigh
	case 'M':
		return formatter.SeverityMedium
	case 'L':
		return formatter.SeverityLow
	default:
		return formatter.SeverityInfo
	}
}

// updateSummary tracks finding counts for summary.
func (a *FormatterAdapter) updateSummary(f formatter.Finding) {
	a.summary.TotalFindings++
	switch f.Severity {
	case formatter.SeverityCritical:
		a.summary.CriticalCount++
	case formatter.SeverityHigh:
		a.summary.HighCount++
	case formatter.SeverityMedium:
		a.summary.MediumCount++
	case formatter.SeverityLow:
		a.summary.LowCount++
	case formatter.SeverityInfo:
		a.summary.InfoCount++
	}
}

// fromCloudRisk converts CloudResource + Risk to capability-sdk Finding.
func (a *FormatterAdapter) fromCloudRisk(cr *output.CloudResource, risk *output.Risk) formatter.Finding {
	if cr == nil || risk == nil {
		return formatter.Finding{}
	}

	return formatter.Finding{
		ID:          risk.Name,
		RuleID:      risk.Name,
		Severity:    a.mapSeverity(risk.Status),
		Title:       risk.Name,
		Description: risk.Description,
		Remediation: risk.Recommendation,
		References:  a.splitReferences(risk.References),
		Location: formatter.Location{
			ResourceARN:  cr.ResourceID,
			ResourceType: cr.ResourceType,
			Region:       cr.Region,
			AccountID:    cr.AccountRef,
		},
		Source:    risk.Source,
		Timestamp: time.Now(),
		Raw:       cr,
	}
}

// fromSecretFinding converts SecretFinding to capability-sdk Finding.
func (a *FormatterAdapter) fromSecretFinding(sf *output.SecretFinding) formatter.Finding {
	if sf == nil {
		return formatter.Finding{}
	}

	return formatter.Finding{
		ID:          fmt.Sprintf("%s-%s", sf.RuleTextID, a.hashShort(sf.ResourceRef)),
		RuleID:      sf.RuleTextID,
		Severity:    a.mapConfidenceToSeverity(sf.Confidence),
		Title:       sf.RuleName,
		Description: fmt.Sprintf("Secret detected: %s", sf.RuleName),
		Location: formatter.Location{
			ResourceARN: sf.ResourceRef,
			FilePath:    sf.FilePath,
			StartLine:   sf.LineNumber,
		},
		Source:    "noseyparker",
		Timestamp: time.Now(),
		Raw:       sf,
	}
}

// splitReferences splits newline-delimited references into slice.
func (a *FormatterAdapter) splitReferences(refs string) []string {
	if refs == "" {
		return nil
	}
	lines := strings.Split(refs, "\n")
	var result []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// mapConfidenceToSeverity converts SecretFinding.Confidence to Severity.
func (a *FormatterAdapter) mapConfidenceToSeverity(confidence string) formatter.Severity {
	switch strings.ToLower(confidence) {
	case "high":
		return formatter.SeverityHigh
	case "medium":
		return formatter.SeverityMedium
	default:
		return formatter.SeverityLow
	}
}

// hashShort returns first 8 chars of SHA256 hash.
func (a *FormatterAdapter) hashShort(s string) string {
	hash := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", hash[:4])
}
