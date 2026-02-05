// pkg/links/gcp/base/native_base.go
package base

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/option"
)

// NativeGCPLink is the base for all GCP links
type NativeGCPLink struct {
	*plugin.BaseLink
	ProjectID       string
	CredentialsFile string
}

func NewNativeGCPLink(name string, args map[string]any) *NativeGCPLink {
	base := plugin.NewBaseLink(name, args)
	return &NativeGCPLink{
		BaseLink:        base,
		ProjectID:       base.ArgString("project", ""),
		CredentialsFile: base.ArgString("credentials", ""),
	}
}

// ClientOptions returns Google API client options
func (l *NativeGCPLink) ClientOptions() []option.ClientOption {
	var opts []option.ClientOption
	if l.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(l.CredentialsFile))
	}
	return opts
}

// StandardGCPParams returns common GCP parameters
func StandardGCPParams() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to credentials JSON file"),
	}
}
