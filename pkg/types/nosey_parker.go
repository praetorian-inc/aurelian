package types

// NoseyParkerInput represents the JSONL format expected by noseyparker
type NpInput struct {
	ContentBase64 string       `json:"content_base64,omitempty"`
	Content       string       `json:"content,omitempty"`
	Provenance    NpProvenance `json:"provenance"`
}

// Provenance contains metadata about the scanned content
type NpProvenance struct {
	Platform     string `json:"platform"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Region       string `json:"region,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
}
