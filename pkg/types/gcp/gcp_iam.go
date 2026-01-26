package gcptypes

// Policies or resource policies are attached to a resource (if resource can host policies)
type Policies struct {
	Allow *AllowPolicy `json:"allow,omitempty"` // only one per resource, make nil if not fetching or resource doesn't host
	Deny  []DenyPolicy `json:"deny,omitempty"`  // can be multiple and only hosted by org/folder/project
}

// resource is acted on (TODO: only care about ones that host policies? or all?); all are CAI types, will translate to tabularium (TODO: direct import?)
type Resource struct {
	AssetType    string            `json:"assetType"`
	URI          string            `json:"uri"`
	ParentURI    string            `json:"parentUri,omitempty"` // where is it defined (and translate to accountRef in tabularium)
	Name         string            `json:"name,omitempty"`
	Location     string            `json:"location,omitempty"`     // region zone
	Service      string            `json:"service,omitempty"`      // storage.googleapis.com, resourcemanager.googleapis.com, etc. (TODO: check if needed)
	ResourceKind string            `json:"resourceKind,omitempty"` // like bucket, vm, etc. (can be used for the resource map in cli modules, maybe)
	Properties   map[string]string `json:"properties,omitempty"`
	Policies     Policies          `json:"policies"`
}

type AllowBinding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
}

type AllowPolicy struct {
	Version     int            `json:"version,omitempty"` // 1 or 3, only 3 has conditions
	Etag        string         `json:"etag,omitempty"`
	Bindings    []AllowBinding `json:"bindings,omitempty"`
	ResourceURI string         `json:"resourceUri"`
}

type DenyRule struct {
	DeniedPrincipals    []string   `json:"deniedPrincipals,omitempty"`
	DeniedPermissions   []string   `json:"deniedPermissions,omitempty"`
	ExceptionPrincipals []string   `json:"exceptionPrincipals,omitempty"`
	Condition           *Condition `json:"condition,omitempty"`
	Description         string     `json:"description,omitempty"`
}

type DenyPolicy struct {
	Name      string     `json:"name"`
	Etag      string     `json:"etag,omitempty"`
	Rules     []DenyRule `json:"rules,omitempty"`
	ParentURI string     `json:"parentUri"` // container that hosts deny (org/folder/project)
}

type Condition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// always CEL; allow uses full CEL; deny uses only resource tag funcs; PAB uses CEL on principal set
	Expression string `json:"expression,omitempty"`
}

// effective boundary applicable and inherited from containers
type PABRule struct {
	Description string   `json:"description,omitempty"`
	Resources   []string `json:"resources"`
}

type PABPolicy struct {
	// defined at org like: organizations/ORG/locations/global/principalAccessBoundaryPolicies/POLICY_ID
	Name               string    `json:"name"`
	DisplayName        string    `json:"displayName,omitempty"`
	EnforcementVersion string    `json:"enforcementVersion,omitempty"` // TODO: check if needed
	Rules              []PABRule `json:"rules"`
	Etag               string    `json:"etag,omitempty"`
}

// applied to a principal set
type PABBinding struct {
	Name            string     `json:"name,omitempty"`
	PolicyName      string     `json:"policyName"` // PABPolicy.Name - the primary reference
	PrincipalSetURI string     `json:"principalSetUri"`
	Condition       *Condition `json:"condition,omitempty"`
	// this is the container that has the principal set which hosts this binding
	ParentURI string `json:"parentUri"`
}

type Permission string

type Role struct {
	Name                string       `json:"name"` // roles/viewer OR organizations/{ORG}/roles/{ID} OR projects/{PROJECT}/roles/{ID}
	Title               string       `json:"title,omitempty"`
	Description         string       `json:"description,omitempty"`
	Stage               string       `json:"stage,omitempty"`
	IncludedPermissions []Permission `json:"includedPermissions,omitempty"` // expanded for evaluation
	ParentURI           string       `json:"parentUri,omitempty"`           // org/project for custom role (empty for predefined)
	Etag                string       `json:"etag,omitempty"`
}
