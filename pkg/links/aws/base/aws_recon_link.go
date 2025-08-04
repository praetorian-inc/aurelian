package base

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AwsReconLink struct {
	*AwsReconBaseLink
	Regions []string
}

func NewAwsReconLink(link chain.Link, configs ...cfg.Config) *AwsReconLink {
	a := &AwsReconLink{}
	a.AwsReconBaseLink = NewAwsReconBaseLink(link, configs...)
	return a
}

func (a *AwsReconLink) Params() []cfg.Param {
	return options.AwsCommonReconOptions()
}

// Initializes common AWS recon link parameters
func (a *AwsReconLink) Initialize() error {

	// First initialize the base link to ensure Profile, ProfileDir, etc. are set
	if err := a.AwsReconBaseLink.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize base link: %w", err)
	}

	a.ContextHolder = cfg.NewContextHolder()

	regions, err := cfg.As[[]string](a.Arg("regions"))
	slog.Debug("AWS recon regions", "regions", regions)
	if err != nil || len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		a.Regions, err = helpers.EnabledRegions(a.Profile, options.JanusArgsAdapter(a.Params(), a.Args()))
		if err != nil {
			return err
		}
	} else {
		a.Regions = regions
	}

	slog.Debug("AWS recon link initialized", "regions", a.Regions, "profile", a.Profile)

	err = a.validateResourceRegions()
	if err != nil {
		return err
	}

	return nil
}

// validateResourceRegions ensures that if global services are requested,
// the "us-east-1" region is included in the list of regions.
func (a *AwsReconLink) validateResourceRegions() error {
	// validate us-east-1 is in the regions list if global services are requested
	rtype, err := cfg.As[[]string](a.Arg(options.AwsResourceType().Name()))
	if err != nil {
		return fmt.Errorf("failed to get resource type: %w", err)
	}

	for _, r := range rtype {
		if helpers.IsGlobalService(r) && !slices.Contains(a.Regions, "us-east-1") {
			return errors.New("global services are only supported in us-east-1")
		}
	}

	return nil
}
