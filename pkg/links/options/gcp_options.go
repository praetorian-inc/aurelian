package options

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// Janus Options

func GcpCredentialsFile() cfg.Param {
	return cfg.NewParam[string]("creds-file", "Path to GCP credentials JSON file").WithDefault("").WithShortcode("c")
}

func GcpProject() cfg.Param {
	return cfg.NewParam[[]string]("project", "GCP project ID").WithDefault([]string{}).WithShortcode("p")
}

func GcpIncludeSysProjects() cfg.Param {
	return cfg.NewParam[bool]("include-sys-projects", "Include system projects like Apps Script projects").WithDefault(false)
}

func GcpOrg() cfg.Param {
	return cfg.NewParam[[]string]("org", "GCP organization ID").WithDefault([]string{}).WithShortcode("o")
}

func GcpFolder() cfg.Param {
	return cfg.NewParam[[]string]("folder", "GCP folder ID").WithDefault([]string{}).WithShortcode("f")
}

func GcpZone() cfg.Param {
	return cfg.NewParam[string]("zone", "GCP zone containing the resource").WithDefault("").WithShortcode("z")
}

func GcpRegion() cfg.Param {
	return cfg.NewParam[string]("region", "GCP region containing the resource").WithDefault("").WithShortcode("r")
}

func GcpResource() cfg.Param {
	return cfg.NewParam[string]("resource", "GCP resource ID").WithDefault("").WithShortcode("r")
}

func GcpResourceTypes() cfg.Param {
	return cfg.NewParam[[]string]("type", "GCP resource types to list").WithDefault([]string{"all"}).WithShortcode("t")
}

func GcpAssetAPIProject() cfg.Param {
	return cfg.NewParam[string]("asset-api-project", "GCP project ID where Asset API is enabled (defaults to ADC project for org/folder, scoped project otherwise)").WithDefault("")
}
