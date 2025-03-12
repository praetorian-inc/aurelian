package base

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsReconLink struct {
	*chain.Base
	Regions    []string
	Profile    string
	ProfileDir string
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
	slog.Debug("AWS recon profile", "profile", profile)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}
	a.Profile = profile

	profileDir, err := cfg.As[string](a.Arg("profile-dir"))
	slog.Debug("AWS recon profile dir", "profile-dir", profileDir)
	if err != nil {
		return fmt.Errorf("failed to get profile dir: %w", err)
	}
	a.ProfileDir = profileDir

	regions, err := cfg.As[[]string](a.Arg("regions"))
	slog.Debug("AWS recon regions", "regions", regions)
	if err != nil || len(regions) == 0 || strings.ToLower(regions[0]) == "all" {
		a.Regions, err = helpers.EnabledRegions(a.Profile, options.JanusParamAdapter(a.Params()))
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

func (a *AwsReconLink) GetConfig(region string, opts []*types.Option) (aws.Config, error) {
	optFns := []func(*config.LoadOptions) error{}
	if a.ProfileDir != "" {
		optFns = append(optFns, config.WithSharedConfigFiles([]string{filepath.Join(a.ProfileDir, "config")}))
		optFns = append(optFns, config.WithSharedCredentialsFiles([]string{filepath.Join(a.ProfileDir, "credentials")}))
	}
	return helpers.GetAWSCfg(region, a.Profile, opts, optFns...)
}
