package base

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type GcpReconLink struct {
	*GcpReconBaseLink
	Projects []string
	Regions  []string
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

	projects, err := cfg.As[[]string](g.Arg("projects"))
	if err != nil {
		return fmt.Errorf("failed to get projects: %w", err)
	}
	g.Projects = projects

	regions, err := cfg.As[[]string](g.Arg("regions"))
	if err != nil {
		return fmt.Errorf("failed to get regions: %w", err)
	}
	g.Regions = regions

	slog.Debug("GCP recon link initialized", "projects", g.Projects, "regions", g.Regions)

	return nil
}
