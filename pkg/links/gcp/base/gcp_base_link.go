package base

import (
	"fmt"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type GcpBaseLink struct {
	*chain.Base
	CredentialsFile string
	ClientOptions   []option.ClientOption
}

func NewGcpBaseLink(link chain.Link, configs ...cfg.Config) *GcpBaseLink {
	g := &GcpBaseLink{}
	g.Base = chain.NewBase(link, configs...)
	return g
}

func (g *GcpBaseLink) Params() []cfg.Param {
	return []cfg.Param{options.GcpCredentialsFile()}
}

// TODO: add support for SSO auth, access token, and service account impersonation
// will need to make creds-file optional
func (g *GcpBaseLink) Initialize() error {
	g.CredentialsFile, _ = cfg.As[string](g.Arg("creds-file"))
	if g.CredentialsFile != "" { // main auth method for GCP
		g.ClientOptions = append(g.ClientOptions, option.WithCredentialsFile(g.CredentialsFile))
	} else {
		// attempt to use application default credentials or default auth that SDK can find
		_, err := google.FindDefaultCredentials(g.Context())
		if err != nil {
			return fmt.Errorf("cannot find default credentials: %w", err)
		}
	}
	return nil
}
