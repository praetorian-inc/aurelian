package options

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Janus Options

func GcpCredentialsFile() plugin.Parameter {
	return plugin.NewParam[string]("creds-file", "Path to GCP credentials JSON file",
		plugin.WithDefault(""),
		plugin.WithShortcode("c"),
		plugin.WithRequired(),
	)
}

func GcpProject() plugin.Parameter {
	return plugin.NewParam[[]string]("project", "GCP project ID",
		plugin.WithDefault([]string{}),
		plugin.WithRequired(),
		plugin.WithShortcode("p"),
	)
}

func GcpFilterSysProjects() plugin.Parameter {
	return plugin.NewParam[bool]("filter-sys-projects", "Filter out system projects like Apps Script projects",
		plugin.WithDefault(true),
	)
}

func GcpOrg() plugin.Parameter {
	return plugin.NewParam[[]string]("org", "GCP organization ID",
		plugin.WithDefault([]string{}),
		plugin.WithRequired(),
		plugin.WithShortcode("o"),
	)
}

func GcpFolder() plugin.Parameter {
	return plugin.NewParam[[]string]("folder", "GCP folder ID",
		plugin.WithDefault([]string{}),
		plugin.WithRequired(),
	)
}

func GcpResourceType() plugin.Parameter {
	return plugin.NewParam[string]("resource-type", "GCP resource type",
		plugin.WithDefault(""),
		plugin.WithRequired(),
		plugin.WithShortcode("t"),
	)
}

func GcpZone() plugin.Parameter {
	return plugin.NewParam[string]("zone", "GCP zone containing the resource",
		plugin.WithDefault(""),
		plugin.WithRequired(),
		plugin.WithShortcode("z"),
	)
}

func GcpRegion() plugin.Parameter {
	return plugin.NewParam[string]("region", "GCP region containing the resource",
		plugin.WithDefault(""),
		plugin.WithRequired(),
		plugin.WithShortcode("r"),
	)
}

func GcpResource() plugin.Parameter {
	return plugin.NewParam[string]("resource", "GCP resource ID",
		plugin.WithDefault(""),
		plugin.WithRequired(),
		plugin.WithShortcode("r"),
	)
}
