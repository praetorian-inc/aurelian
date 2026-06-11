// Package publicresource builds a standardized capmodel.Risk for a publicly
// exposed cloud resource. It is CSP-agnostic: AWS, Azure, and GCP emission
// sites map their native results into PublicResource and call NewRisk, which
// renders a structured capmodel.Proof shared across all providers.
package publicresource

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// proofFormat is the proof schema version. Kept identical to the value emitted
// by pkg/aws/cloudfront/risk.go (#209) so all Phase 0 (LAB-3740) migrations
// share one format string; the per-risk shape is discriminated by Risk.Name.
const proofFormat = "v1.0.0"

// Fact is one exposure-evidence key/value row.
type Fact struct {
	Key      string
	Value    string
	Copyable bool
}

// NamedList is a titled list of strings rendered as its own proof section
// (e.g. "Allowed Actions", "Evaluation Reasons", "Public URLs").
type NamedList struct {
	Title string
	Items []string
}

// PublicResource is the CSP-agnostic description of a publicly exposed cloud
// resource. Each provider's emission site maps its native result into this
// struct; NewRisk renders the standardized proof.
type PublicResource struct {
	Provider     string // "AWS" | "Azure" | "GCP"
	RiskName     string // per-CSP Guard rule key, e.g. "public-aws-resource"
	ResourceType string // native type string
	ResourceID   string // canonical identifier (ARN / Azure resource ID / GCP resource ID) -> Risk.TargetName
	ResourceName string // optional display name
	Region       string // AWS region / Azure location / GCP location (optional)
	Scope        string // account ID / subscription ID / project ID
	ScopeLabel   string // "AWS Account" / "Azure Subscription" / "GCP Project"
	Severity     output.RiskSeverity
	Summary      string         // one-paragraph description of the exposure
	Exposure     []Fact         // what makes the resource public
	Lists        []NamedList    // extra evidence lists, one section each
	References   []string       // optional reference URLs
	Properties   map[string]any // raw resource properties appendix (optional)
}

// NewRisk builds a platform capmodel.Risk with a standardized public-resource
// proof. It returns an error only when required identity fields are missing or
// the proof fails to marshal.
func NewRisk(r PublicResource) (capmodel.Risk, error) {
	if r.RiskName == "" {
		return capmodel.Risk{}, fmt.Errorf("public resource risk requires a non-empty RiskName")
	}
	if r.ResourceID == "" {
		return capmodel.Risk{}, fmt.Errorf("public resource risk requires a non-empty ResourceID")
	}

	proof, err := json.Marshal(buildProof(r))
	if err != nil {
		return capmodel.Risk{}, err
	}

	return capmodel.Risk{
		TargetName: r.ResourceID,
		Name:       r.RiskName,
		Source:     "aurelian",
		Status:     severityToStatus(r.Severity),
		Proof:      proof,
		// TODO(LAB-3740): populate a typed capmodel asset once Aurelian emits the
		// SDK `_type` envelope and Guard's ingest consumes Risk.Target. Same TODO as
		// pkg/aws/cloudfront/risk.go (LAB-3995) — inert until then.
		Target: nil,
	}, nil
}

// buildProof assembles the shared proof layout. Empty sections are omitted.
func buildProof(r PublicResource) capmodel.Proof {
	sections := []capmodel.ProofSection{
		{Title: "Summary", Elements: []capmodel.ProofElement{paragraph(r.Summary)}},
	}

	if resourceRows := resourceRows(r); len(resourceRows) > 0 {
		sections = append(sections, capmodel.ProofSection{
			Title:    "Resource",
			Elements: []capmodel.ProofElement{keyValue(resourceRows)},
		})
	}

	if exposureRows := factRows(r.Exposure); len(exposureRows) > 0 {
		sections = append(sections, capmodel.ProofSection{
			Title:    "Exposure",
			Elements: []capmodel.ProofElement{keyValue(exposureRows)},
		})
	}

	for _, nl := range r.Lists {
		if len(nl.Items) == 0 {
			continue
		}
		sections = append(sections, capmodel.ProofSection{
			Title:    nl.Title,
			Elements: []capmodel.ProofElement{list(nl.Items)},
		})
	}

	if len(r.References) > 0 {
		sections = append(sections, capmodel.ProofSection{
			Title:    "References",
			Elements: []capmodel.ProofElement{referenceList(r.References)},
		})
	}

	if len(r.Properties) > 0 {
		if content, err := json.MarshalIndent(r.Properties, "", "  "); err == nil {
			sections = append(sections, capmodel.ProofSection{
				Title:    "Resource Properties",
				Elements: []capmodel.ProofElement{codeBlock("json", string(content))},
			})
		}
	}

	return capmodel.Proof{Format: proofFormat, Sections: sections}
}

// resourceRows builds the identity key/value rows, skipping empty values.
func resourceRows(r PublicResource) []capmodel.ProofKeyValueRow {
	candidates := []capmodel.ProofKeyValueRow{
		{Key: "Provider", Value: r.Provider},
		{Key: "Resource Type", Value: r.ResourceType},
		{Key: "Resource ID", Value: r.ResourceID, Copyable: true},
		{Key: "Name", Value: r.ResourceName},
		{Key: "Region", Value: r.Region},
		{Key: r.ScopeLabel, Value: r.Scope, Copyable: true},
	}
	rows := make([]capmodel.ProofKeyValueRow, 0, len(candidates))
	for _, row := range candidates {
		if row.Key == "" || row.Value == "" {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

// factRows converts exposure facts into key/value rows, skipping empty values.
func factRows(facts []Fact) []capmodel.ProofKeyValueRow {
	rows := make([]capmodel.ProofKeyValueRow, 0, len(facts))
	for _, f := range facts {
		if f.Key == "" || f.Value == "" {
			continue
		}
		rows = append(rows, capmodel.ProofKeyValueRow{Key: f.Key, Value: f.Value, Copyable: f.Copyable})
	}
	return rows
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

func codeBlock(language, content string) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "code_block", CodeBlock: &capmodel.ProofCodeBlock{Language: language, Content: content}}
}
