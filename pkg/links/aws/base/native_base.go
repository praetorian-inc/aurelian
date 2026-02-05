// pkg/links/aws/base/native_base.go
package base

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// NativeAWSLink is the base for all AWS links (replaces AwsReconBaseLink)
type NativeAWSLink struct {
	*plugin.BaseLink
	Profile    string
	ProfileDir string
	Regions    []string
}

func NewNativeAWSLink(name string, args map[string]any) *NativeAWSLink {
	base := plugin.NewBaseLink(name, args)
	return &NativeAWSLink{
		BaseLink:   base,
		Profile:    base.ArgString("profile", ""),
		ProfileDir: base.ArgString("profile-dir", ""),
		Regions:    base.ArgStringSlice("regions", []string{"all"}),
	}
}

// GetConfig returns AWS SDK config for the specified region
func (l *NativeAWSLink) GetConfig(ctx context.Context, region string) (aws.Config, error) {
	var opts []*types.Option
	if l.ProfileDir != "" {
		opts = append(opts, &types.Option{Name: "profile-dir", Value: l.ProfileDir})
	}
	return helpers.GetAWSCfg(region, l.Profile, opts, "")
}

// StandardAWSParams returns common AWS parameters
func StandardAWSParams() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("profile", "AWS profile name", plugin.WithShortcode("p")),
		plugin.NewParam[string]("profile-dir", "AWS profile directory"),
		plugin.NewParam[[]string]("regions", "AWS regions to query", plugin.WithDefault([]string{"all"})),
	}
}
