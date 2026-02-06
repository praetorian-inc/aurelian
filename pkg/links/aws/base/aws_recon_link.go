package base

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AwsReconLink extends AwsReconBaseLink with region support
type AwsReconLink struct {
	*AwsReconBaseLink
	Regions []string
}

func NewAwsReconLink(name string, args map[string]any) *AwsReconLink {
	return &AwsReconLink{
		AwsReconBaseLink: NewAwsReconBaseLink(name, args),
	}
}

func (a *AwsReconLink) Parameters() []plugin.Parameter {
	baseParams := a.AwsReconBaseLink.Parameters()
	additionalParams := []plugin.Parameter{
		plugin.NewParam[[]string]("regions", "AWS regions to query", plugin.WithDefault([]string{"all"})),
		plugin.NewParam[[]string]("resource-type", "AWS resource types to enumerate"),
	}
	return append(baseParams, additionalParams...)
}

// Initialize initializes common AWS recon link parameters
func (a *AwsReconLink) Initialize(ctx context.Context) error {
	// First initialize the base link to ensure Profile, ProfileDir, etc. are set
	if err := a.AwsReconBaseLink.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize base link: %w", err)
	}

	regions := a.ArgStringSlice("regions", []string{})
	slog.Debug("AWS recon regions", "regions", regions)

	if len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		// Convert args to Options
		var opts []*types.Option
		if profileDir := a.ArgString("profile-dir", ""); profileDir != "" {
			opts = append(opts, &types.Option{Name: "profile-dir", Value: profileDir})
		}

		var err error
		a.Regions, err = helpers.EnabledRegions(a.Profile, opts)
		if err != nil {
			return err
		}
	} else {
		a.Regions = regions
	}

	slog.Debug("AWS recon link initialized", "regions", a.Regions, "profile", a.Profile)

	err := a.validateResourceRegions()
	if err != nil {
		return err
	}

	return nil
}

// validateResourceRegions ensures that if global services are requested,
// the "us-east-1" region is included in the list of regions.
func (a *AwsReconLink) validateResourceRegions() error {
	// validate us-east-1 is in the regions list if global services are requested
	rtype := a.ArgStringSlice("resource-type", []string{})

	for _, r := range rtype {
		if helpers.IsGlobalService(r) && !slices.Contains(a.Regions, "us-east-1") {
			return errors.New("global services are only supported in us-east-1")
		}
	}

	return nil
}
