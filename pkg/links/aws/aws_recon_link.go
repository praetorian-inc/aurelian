package aws

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AwsReconLink struct {
	*chain.Base
	regions []string
	profile string
}

func NewAwsReconLink(link chain.Link, configs ...cfg.Config) *AwsReconLink {
	a := &AwsReconLink{}
	a.Base = chain.NewBase(link, configs...)
	return a
}

func (a *AwsReconLink) Params() []cfg.Param {
	return options.AwsCommonReconOptions()
}

// Initializes common AWS recon link parameters
func (a *AwsReconLink) Initialize() error {
	a.ContextHolder = cfg.NewContextHolder()

	profile, err := cfg.As[string](a.Arg("profile"))
	slog.Debug("cloudcontrol profile", "profile", profile)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}
	a.profile = profile

	regions, err := cfg.As[[]string](a.Arg("regions"))
	slog.Info("cloudcontrol regions", "regions", regions)
	if err != nil || len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		a.regions, err = helpers.EnabledRegions(a.profile, options.JanusParamAdapter(a.Params()))
		if err != nil {
			return err
		}
	} else {
		a.regions = regions
	}

	slog.Debug("initialized", "regions", a.regions, "profile", a.profile)

	return nil
}
