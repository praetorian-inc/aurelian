package base

import (
	"fmt"
	"log/slog"

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
	return options.GcpBaseOptions()
}

func (g *GcpBaseLink) Initialize() error {
	g.ContextHolder = cfg.NewContextHolder()
	credentialsFile, err := cfg.As[string](g.Arg("creds-file"))
	if err != nil {
		return fmt.Errorf("failed to get credentials-file: %w", err)
	}
	g.CredentialsFile = credentialsFile
	if g.CredentialsFile != "" {
		g.ClientOptions = append(g.ClientOptions, option.WithCredentialsFile(g.CredentialsFile))
	} else {
		// Use Application Default Credentials
		_, err := google.FindDefaultCredentials(g.Context())
		if err != nil {
			return fmt.Errorf("cannot find default credentials: %w", err)
		}
	}
	slog.Debug("GCP global link initialized", "credentials-file", g.CredentialsFile)
	return nil
}
