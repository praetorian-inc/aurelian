package base

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AwsReconBaseLink is the native plugin version for AWS recon
type AwsReconBaseLink struct {
	*plugin.BaseLink
	Profile    string
	ProfileDir string
}

func NewAwsReconBaseLink(name string, args map[string]any) *AwsReconBaseLink {
	base := plugin.NewBaseLink(name, args)
	return &AwsReconBaseLink{
		BaseLink:   base,
		Profile:    base.ArgString("profile", ""),
		ProfileDir: base.ArgString("profile-dir", ""),
	}
}

func (a *AwsReconBaseLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("profile", "AWS profile name", plugin.WithShortcode("p")),
		plugin.NewParam[string]("profile-dir", "AWS profile directory"),
		plugin.NewParam[string]("opsec_level", "OPSEC level", plugin.WithDefault("none")),
	}
}

func (a *AwsReconBaseLink) Initialize(ctx context.Context) error {
	// Profile and ProfileDir are already set in constructor
	slog.Debug("AWS recon global link initialized", "profile", a.Profile, "profile-dir", a.ProfileDir)
	return nil
}

func (a *AwsReconBaseLink) GetOpsecLevel() string {
	return a.ArgString("opsec_level", "none")
}

func (a *AwsReconBaseLink) GetConfig(ctx context.Context, region string, opts []*types.Option) (aws.Config, error) {
	optFns := []func(*config.LoadOptions) error{}
	if a.ProfileDir != "" {
		optFns = append(optFns, config.WithSharedConfigFiles([]string{filepath.Join(a.ProfileDir, "config")}))
		optFns = append(optFns, config.WithSharedCredentialsFiles([]string{filepath.Join(a.ProfileDir, "credentials")}))
	}

	return helpers.GetAWSCfg(region, a.Profile, opts, a.GetOpsecLevel(), optFns...)
}

// GetConfigWithRuntimeArgs gets AWS config using runtime arguments instead of default values
func (a *AwsReconBaseLink) GetConfigWithRuntimeArgs(ctx context.Context, region string) (aws.Config, error) {
	// Convert args to Options - since we're using native plugin, extract from BaseLink args
	var opts []*types.Option
	if profileDir := a.ArgString("profile-dir", ""); profileDir != "" {
		opts = append(opts, &types.Option{Name: "profile-dir", Value: profileDir})
	}
	return a.GetConfig(ctx, region, opts)
}
