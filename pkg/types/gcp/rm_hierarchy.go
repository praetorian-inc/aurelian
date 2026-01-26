package gcptypes

type Hierarchy struct {
	Organizations []*Organization     `json:"organizations,omitempty"`
	Ancestors     map[string][]string `json:"ancestors,omitempty"` // maps child container URIs (folder or project) to ordered ancestor URIs, closest-first, ending at org
}

type Organization struct {
	URI         string            `json:"uri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	OrganizationNumber string      `json:"organizationNumber"`
	DirectoryCustomer  string      `json:"directoryCustomer,omitempty"`
	Folders            []*Folder   `json:"folders,omitempty"`
	Projects           []*Project  `json:"projects,omitempty"`
	Policies           Policies    `json:"policies"`
	PABPolicies        []PABPolicy `json:"pabPolicies,omitempty"`
}

type Folder struct {
	URI         string            `json:"uri"`
	ParentURI   string            `json:"parentUri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	FolderNumber string     `json:"folderNumber"`
	Folders      []*Folder  `json:"folders,omitempty"`
	Projects     []*Project `json:"projects,omitempty"`
	Policies     Policies   `json:"policies"`
}

type Project struct {
	URI         string            `json:"uri"`
	ParentURI   string            `json:"parentUri"`
	DisplayName string            `json:"displayName,omitempty"`
	CreateTime  string            `json:"createTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	ProjectNumber  string   `json:"projectNumber"`
	ProjectID      string   `json:"projectId"`
	BillingAccount string   `json:"billingAccount,omitempty"`
	Policies       Policies `json:"policies"`
	Services       []string `json:"services,omitempty"` // enabled services
}

func (org *Organization) ToResource() *Resource {
	properties := make(map[string]string)
	properties["organizationNumber"] = org.OrganizationNumber
	if org.DirectoryCustomer != "" {
		properties["directoryCustomer"] = org.DirectoryCustomer
	}
	if org.CreateTime != "" {
		properties["createTime"] = org.CreateTime
	}
	for k, v := range org.Labels {
		properties["label:"+k] = v
	}
	return &Resource{
		AssetType:  "cloudresourcemanager.googleapis.com/Organization",
		URI:        org.URI,
		Name:       org.DisplayName,
		Properties: properties,
		Policies:   org.Policies,
	}
}

func (folder *Folder) ToResource() *Resource {
	properties := make(map[string]string)
	properties["folderNumber"] = folder.FolderNumber
	if folder.CreateTime != "" {
		properties["createTime"] = folder.CreateTime
	}
	for k, v := range folder.Labels {
		properties["label:"+k] = v
	}
	return &Resource{
		AssetType:  "cloudresourcemanager.googleapis.com/Folder",
		URI:        folder.URI,
		ParentURI:  folder.ParentURI,
		Name:       folder.DisplayName,
		Properties: properties,
		Policies:   folder.Policies,
	}
}

func (project *Project) ToResource() *Resource {
	properties := make(map[string]string)
	properties["projectNumber"] = project.ProjectNumber
	properties["projectId"] = project.ProjectID
	if project.BillingAccount != "" {
		properties["billingAccount"] = project.BillingAccount
	}
	if project.CreateTime != "" {
		properties["createTime"] = project.CreateTime
	}
	for k, v := range project.Labels {
		properties["label:"+k] = v
	}
	return &Resource{
		AssetType:  "cloudresourcemanager.googleapis.com/Project",
		URI:        project.URI,
		ParentURI:  project.ParentURI,
		Name:       project.DisplayName,
		Properties: properties,
		Policies:   project.Policies,
	}
}
