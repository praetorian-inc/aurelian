package base

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type GcpBaseLink struct {
	*plugin.BaseLink
	ClientOptions []option.ClientOption
}

func NewGcpBaseLink(name string, args map[string]any) *GcpBaseLink {
	return &GcpBaseLink{
		BaseLink: plugin.NewBaseLink(name, args),
	}
}

func (g *GcpBaseLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP service account credentials JSON file"),
	}
}

// TODO: add support for SSO auth, access token, and service account impersonation
// will need to make credentials optional
func (g *GcpBaseLink) Initialize(ctx context.Context) error {
	credsFile := g.ArgString("credentials", "")
	if credsFile != "" { // main auth method for GCP
		g.ClientOptions = append(g.ClientOptions, option.WithCredentialsFile(credsFile))
	} else {
		// attempt to use application default credentials or default auth that SDK can find
		_, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return fmt.Errorf("cannot find default credentials: %w", err)
		}
	}
	return nil
}
