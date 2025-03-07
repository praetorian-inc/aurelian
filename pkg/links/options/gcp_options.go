package options

import (
	"regexp"

	"github.com/praetorian-inc/nebula/pkg/types"
)

var GcpProjectIdOpt = types.Option{
	Name:        "project-id",
	Short:       "p",
	Description: "GCP project ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var GcpFolderIdOpt = types.Option{
	Name:        "folder-id",
	Short:       "f",
	Description: "GCP folder ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var GcpOrganizationIdOpt = types.Option{
	Name:        "org-id",
	Description: "GCP organization ID",
	Required:    true,
	Type:        types.String,
	Value:       "",
	ValueFormat: regexp.MustCompile("^[0-9]{12}$"),
}

var GcpProjectsListOpt = types.Option{
	Name:        "projects-list",
	Short:       "",
	Description: "GCP projects list",
	Required:    true,
	Type:        types.String,
	Value:       "",
}

var GcpIncludeAncestorsOpt = types.Option{
	Name:        "ancestors",
	Short:       "",
	Description: "include ancestors",
	Required:    true,
	Type:        types.String,
	Value:       "",
}
