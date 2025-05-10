package base

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsReconBaseLink struct {
	*chain.Base
	Profile    string
	ProfileDir string
}

func NewAwsReconBaseLink(link chain.Link, configs ...cfg.Config) *AwsReconBaseLink {
	a := &AwsReconBaseLink{}
	a.Base = chain.NewBase(link, configs...)
	return a
}

func (a *AwsReconBaseLink) Params() []cfg.Param {
	return options.AwsReconBaseOptions()
}

func (a *AwsReconBaseLink) Initialize() error {
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

	slog.Debug("AWS recon global link initialized", "profile", a.Profile, "profile-dir", a.ProfileDir)

	return nil
}

func (a *AwsReconBaseLink) GetConfig(region string, opts []*types.Option) (aws.Config, error) {
	optFns := []func(*config.LoadOptions) error{}
	if a.ProfileDir != "" {
		optFns = append(optFns, config.WithSharedConfigFiles([]string{filepath.Join(a.ProfileDir, "config")}))
		optFns = append(optFns, config.WithSharedCredentialsFiles([]string{filepath.Join(a.ProfileDir, "credentials")}))
	}
	return helpers.GetAWSCfg(region, a.Profile, opts, optFns...)
}
