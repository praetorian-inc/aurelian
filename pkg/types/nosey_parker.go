package types

// NoseyParkerInput represents the JSONL format expected by noseyparker
type NpInput struct {
	ContentBase64 string       `json:"content_base64,omitempty"`
	Content       string       `json:"content,omitempty"`
	Provenance    NpProvenance `json:"provenance"`
}

// Provenance contains metadata about the scanned content
type NpProvenance struct {
	Platform     string       `json:"platform"`
	ResourceType string       `json:"resource_type"`
	ResourceID   string       `json:"resource_id"`
	Region       string       `json:"region,omitempty"`
	AccountID    string       `json:"account_id,omitempty"`
	FilePath     string       `json:"file_path,omitempty"`
	RepoPath     string       `json:"repo_path,omitempty"`
	FirstCommit  *FirstCommit `json:"first_commit,omitempty"`
}

// FirstCommit represents the first git commit where a secret was found
type FirstCommit struct {
	BlobPath       string         `json:"blob_path"`
	CommitMetadata CommitMetadata `json:"commit_metadata"`
}

// CommitMetadata contains git commit information
type CommitMetadata struct {
	CommitID       string `json:"commit_id"`
	AuthorName     string `json:"author_name"`
	CommitterName  string `json:"committer_name"`
	Message        string `json:"message"`
	CommitDate     string `json:"commit_date"`
	AuthorDate     string `json:"author_date"`
}

// Snippet represents the context around a matched secret
type Snippet struct {
	Before   string `json:"before"`
	Matching string `json:"matching"`
	After    string `json:"after"`
}

// NPFinding represents a secret finding from NoseyParker
type NPFinding struct {
	FindingID  string       `json:"finding_id"`
	RuleID     string       `json:"rule_id"`
	RuleName   string       `json:"rule_name"`
	Match      string       `json:"match"`
	Snippet    Snippet      `json:"snippet"`
	Provenance NpProvenance `json:"provenance"`
	Severity   string       `json:"severity"`
	Confidence string       `json:"confidence"`
}
