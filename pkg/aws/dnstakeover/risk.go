package dnstakeover

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

const proofFormat = "v1.0.0"

// takeoverFinding is the typed input each checker fills to build a takeover risk.
// Per-checker differences are expressed as typed rows/strings, not separate proof
// shapes — buildTakeoverProof renders a single shape for all three checkers.
type takeoverFinding struct {
	riskName       string                      // human-readable Risk.Name
	severity       output.RiskSeverity         // mapped to a Chariot T* status
	rec            Route53Record               // the dangling DNS record
	accountID      string                      // owning AWS account
	summary        string                      // Summary section paragraph
	detailRows     []capmodel.ProofKeyValueRow // checker-specific Record Details rows
	impact         string                      // Impact section paragraph
	recommendation []string                    // Recommendation section list
	references     []string                    // References section list (href)
}

// NewTakeoverRisk builds a platform capmodel.Risk for a subdomain-takeover finding.
// It prepends the common Route53 detail rows (including a copyable Route53 ARN row,
// preserving the old ImpactedResourceID value) to the checker-specific detailRows,
// marshals the structured proof, and returns the risk keyed on the dangling record.
func NewTakeoverRisk(f takeoverFinding) (capmodel.Risk, error) {
	proof, err := json.Marshal(buildTakeoverProof(f))
	if err != nil {
		return capmodel.Risk{}, err
	}

	return capmodel.Risk{
		TargetName: f.rec.RecordName,
		Name:       f.riskName,
		Source:     "aurelian",
		Status:     severityToStatus(f.severity),
		Proof:      proof,
		// TODO(LAB-3740): populate a typed capmodel asset (e.g. capmodel.Domain for the
		// dangling subdomain) once Aurelian emits the SDK `_type` envelope and Guard's
		// ingest consumes Risk.Target. Inert until then — Guard's convertRisk falls back
		// to a bare Asset without a `_type` discriminator.
		Target: nil,
	}, nil
}

// buildTakeoverProof assembles the structured proof: Summary, Record Details (common
// Route53 rows + checker-specific rows), Impact, Recommendation, and References.
func buildTakeoverProof(f takeoverFinding) capmodel.Proof {
	rows := append(commonRecordRows(f.rec, f.accountID), f.detailRows...)

	sections := []capmodel.ProofSection{
		{Title: "Summary", Elements: []capmodel.ProofElement{paragraph(f.summary)}},
		{Title: "Record Details", Elements: []capmodel.ProofElement{keyValue(rows)}},
		{Title: "Impact", Elements: []capmodel.ProofElement{paragraph(f.impact)}},
		{Title: "Recommendation", Elements: []capmodel.ProofElement{list(f.recommendation)}},
		{Title: "References", Elements: []capmodel.ProofElement{referenceList(f.references)}},
	}

	return capmodel.Proof{Format: proofFormat, Sections: sections}
}

// commonRecordRows returns the Route53 detail rows shared by every checker, ending
// with a copyable Route53 ARN row that preserves the legacy ImpactedResourceID value.
func commonRecordRows(rec Route53Record, accountID string) []capmodel.ProofKeyValueRow {
	arn := fmt.Sprintf("arn:aws:route53:::hostedzone/%s/recordset/%s/%s",
		rec.ZoneID, rec.RecordName, rec.Type)

	return []capmodel.ProofKeyValueRow{
		{Key: "Zone Name", Value: rec.ZoneName},
		{Key: "Zone ID", Value: rec.ZoneID, Copyable: true},
		{Key: "Record Name", Value: rec.RecordName, Copyable: true},
		{Key: "Record Type", Value: rec.Type},
		{Key: "Record Values", Value: strings.Join(rec.Values, ", ")},
		{Key: "Account ID", Value: accountID, Copyable: true},
		{Key: "Route53 ARN", Value: arn, Copyable: true},
	}
}

// severityToStatus maps a risk severity to a Chariot triage status code.
func severityToStatus(sev output.RiskSeverity) string {
	switch output.NormalizeSeverity(sev) {
	case output.RiskSeverityCritical:
		return "TC"
	case output.RiskSeverityHigh:
		return "TH"
	case output.RiskSeverityMedium:
		return "TM"
	case output.RiskSeverityLow:
		return "TL"
	default:
		return "TI"
	}
}

func paragraph(text string) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "paragraph", Paragraph: &capmodel.ProofParagraph{Text: text}}
}

func keyValue(rows []capmodel.ProofKeyValueRow) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "key_value", KeyValue: &capmodel.ProofKeyValue{Rows: rows}}
}

func list(items []string) capmodel.ProofElement {
	listItems := make([]capmodel.ProofListItem, 0, len(items))
	for _, item := range items {
		listItems = append(listItems, capmodel.ProofListItem{Label: item})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: listItems}}
}

func referenceList(urls []string) capmodel.ProofElement {
	items := make([]capmodel.ProofListItem, 0, len(urls))
	for _, u := range urls {
		items = append(items, capmodel.ProofListItem{Label: u, Href: u})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: items}}
}
