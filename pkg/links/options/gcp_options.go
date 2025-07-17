package options

import (
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
)

// Janus Options

func GcpCredentialsFile() cfg.Param {
	return cfg.NewParam[string]("creds-file", "Path to GCP credentials JSON file").WithDefault("").WithShortcode("c").AsRequired()
}

func GcpProject() cfg.Param {
	return cfg.NewParam[[]string]("project", "GCP project ID").WithDefault([]string{}).AsRequired().WithShortcode("p")
}

func GcpFilterSysProjects() cfg.Param {
	return cfg.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects").WithDefault(true)
}

func GcpOrg() cfg.Param {
	return cfg.NewParam[[]string]("org", "GCP organization ID").WithDefault([]string{}).AsRequired().WithShortcode("o")
}

func GcpFolder() cfg.Param {
	return cfg.NewParam[[]string]("folder", "GCP folder ID").WithDefault([]string{}).AsRequired().WithShortcode("f")
}

func GcpResourceType() cfg.Param {
	return cfg.NewParam[string]("resource-type", "GCP resource type").WithDefault("").AsRequired().WithShortcode("t")
}

func GcpZone() cfg.Param {
	return cfg.NewParam[string]("zone", "GCP zone containing the resource").WithDefault("").AsRequired().WithShortcode("z")
}

func GcpRegion() cfg.Param {
	return cfg.NewParam[string]("region", "GCP region containing the resource").WithDefault("").AsRequired().WithShortcode("r")
}

func GcpResource() cfg.Param {
	return cfg.NewParam[string]("resource", "GCP resource ID").WithDefault("").AsRequired().WithShortcode("r")
}
