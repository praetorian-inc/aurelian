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

type GcpReconBaseLink struct {
	*chain.Base
	CredentialsFile string
	ClientOptions   []option.ClientOption
}

func NewGcpReconBaseLink(link chain.Link, configs ...cfg.Config) *GcpReconBaseLink {
	g := &GcpReconBaseLink{}
	g.Base = chain.NewBase(link, configs...)
	return g
}

func (g *GcpReconBaseLink) Params() []cfg.Param {
	return options.GcpBaseOptions()
}

func (g *GcpReconBaseLink) Initialize() error {
	g.ContextHolder = cfg.NewContextHolder()
	credentialsFile, err := cfg.As[string](g.Arg("creds-file"))
	if err != nil {
		return fmt.Errorf("failed to get creds-file: %w", err)
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
	slog.Debug("GCP recon global link initialized", "creds-file", g.CredentialsFile)
	return nil
}

type GcpReconLink struct {
	*GcpReconBaseLink
	Project string
}

func NewGcpReconLink(link chain.Link, configs ...cfg.Config) *GcpReconLink {
	g := &GcpReconLink{}
	g.GcpReconBaseLink = NewGcpReconBaseLink(link, configs...)
	return g
}

func (g *GcpReconLink) Params() []cfg.Param {
	return options.GcpCommonReconOptions()
}

func (g *GcpReconLink) Initialize() error {
	if err := g.GcpReconBaseLink.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize base link: %w", err)
	}
	g.ContextHolder = cfg.NewContextHolder()
	project, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.Project = project
	slog.Debug("GCP recon link initialized", "project", g.Project)
	return nil
}
