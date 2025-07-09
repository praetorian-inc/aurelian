package options

import (
	"regexp"

	"github.com/praetorian-inc/janus/pkg/chain/cfg"
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

// Janus Options

func GcpCredentialsFile() cfg.Param {
	return cfg.NewParam[string]("creds-file", "Path to GCP credentials JSON file").WithDefault("").AsRequired().WithShortcode("c")
}

func GcpProject() cfg.Param {
	return cfg.NewParam[string]("project", "GCP project ID").WithDefault("").AsRequired().WithShortcode("p")
}

func GcpBaseOptions() []cfg.Param {
	return []cfg.Param{
		GcpCredentialsFile(),
	}
}

func GcpCommonReconOptions() []cfg.Param {
	return []cfg.Param{
		GcpCredentialsFile(),
		GcpProject(),
	}
}
