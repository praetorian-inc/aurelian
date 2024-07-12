package options

import "regexp"

var GcpProjectIdOpt = Option{
	Name:        "project-id",
	Short:       "p",
	Description: "GCP project ID",
	Required:    true,
	Type:        String,
	Value:       "",
}

var GcpFolderIdOpt = Option{
	Name:        "folder-id",
	Short:       "f",
	Description: "GCP folder ID",
	Required:    true,
	Type:        String,
	Value:       "",
}

var GcpOrganizationIdOpt = Option{
	Name:        "org-id",
	Description: "GCP organization ID",
	Required:    true,
	Type:        String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^[0-9]{12}$"),
}

var GcpProjectsListOpt = Option{
	Name:        "projects-list",
	Short:       "",
	Description: "GCP projects list",
	Required:    true,
	Type:        String,
	Value:       "",
}

var GcpIncludeAncestorsOpt = Option{
	Name:        "ancestors",
	Short:       "",
	Description: "include ancestors",
	Required:    true,
	Type:        String,
	Value:       "",
}
