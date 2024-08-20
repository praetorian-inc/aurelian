package modules

import (
	"encoding/json"
	"log"
)

type Result struct {
	Platform Platform `json:"platform"`
	Module   string   `json:"module"`
	Filename string
	Data     interface{} `json:"data"`
}

type ResultOption func(*Result)

func NewResult(platform Platform, module string, data interface{}, opts ...ResultOption) Result {
	r := &Result{
		Platform: platform,
		Module:   module,
		Data:     data,
	}

	for _, opt := range opts {
		opt(r)
	}
	return *r
}

func WithFilename(filename string) ResultOption {
	return func(r *Result) {
		r.Filename = filename
	}
}

// struct to parse the JSON response from the CloudControl ListResources API
type ListDataResult struct {
	NextToken            string                        `json:"NextToken"`
	ResourceDescriptions []EnrichedResourceDescription `json:"ResourceDescriptions"`
	TypeName             string                        `json:"TypeName"`
	ResultMetadata       interface{}                   `json:"ResultMetadata"`
}

type EnrichedResourceDescription struct {
	Identifier string      `json:"Identifier"`
	Region     string      `json:"Region"` //additional field to enrich
	Properties interface{} `json:"Properties"`
	AccountId  string
}

func (r *Result) String() string {
	d, _ := json.MarshalIndent(r.Data, "", "  ")
	return string(d)
}

func (r *Result) StringData() string {
	return r.Data.(string)
}

func (r *Result) Json() []byte {
	d, _ := json.Marshal(r)
	return d
}

func (r *Result) DataJson() []byte {
	d, _ := json.Marshal(r.Data)
	return d
}

func (r *Result) UnmarshalListData() ListDataResult {
	var dataResult ListDataResult
	err := json.Unmarshal(r.DataJson(), &dataResult)
	if err != nil {
		log.Fatalf("Unable to marshal JSON due to %s", err)
	}
	return dataResult
}

func (listData *ListDataResult) GetIdentifiers() []string {
	var identifiers []string
	for _, resourceDescription := range listData.ResourceDescriptions {
		identifiers = append(identifiers, resourceDescription.Identifier)
	}
	return identifiers
}
