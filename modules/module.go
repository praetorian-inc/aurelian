package modules

import (
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type OpsecLevel string

const (
	Stealth  OpsecLevel = "stealth"
	Moderate OpsecLevel = "moderate"
	None     OpsecLevel = "none"
)

func GetPlatformFromString(platform string) types.Platform {
	switch platform {
	case "aws":
		return AWS
	case "azure":
		return Azure
	case "gcp":
		return GCP
	case "oci":
		return OCI
	case "saas":
		return SaaS
	case "universal":
		return Universal
	default:
		return ""
	}
}

const (
	AWS       types.Platform = "aws"
	Azure     types.Platform = "azure"
	GCP       types.Platform = "gcp"
	OCI       types.Platform = "oci"
	SaaS      types.Platform = "saas"
	Universal types.Platform = "universal"
)

type Metadata struct {
	Id          string
	Name        string
	Description string
	Platform    types.Platform
	Authors     []string
	References  []string
	OpsecLevel  OpsecLevel
}

type Module interface {
	Invoke() error
	GetOutputProviders() []types.OutputProvider
}

type BaseModule struct {
	Module
	Metadata
	Options         []*types.Option
	OutputProviders []types.OutputProvider

	In    any
	Stage any
}

func (m *BaseModule) Invoke() error {
	panic("not implemented")
}

func (m *BaseModule) GetOptionByName(name string) *types.Option {
	return options.GetOptionByName(name, m.Options)
}

func (m *BaseModule) AddOption(option types.Option) {
	m.Options = append(m.Options, &option)
}

func (m *BaseModule) MakeResult(data interface{}, opts ...types.ResultOption) types.Result {
	return types.NewResult(m.Platform, m.Name, data, opts...)
}

func (m *BaseModule) GetOutputProviders() []types.OutputProvider {
	return m.OutputProviders
}

func (m *BaseModule) ConfigureOutputProviders(providers []func(options []*types.Option) types.OutputProvider) {
	for _, p := range providers {
		m.OutputProviders = append(m.OutputProviders, p(m.Options))
	}
}

func RenderOutputProviders(providers []func(options []*types.Option) types.OutputProvider, opts []*types.Option) []types.OutputProvider {
	op := []types.OutputProvider{}
	for _, p := range providers {
		op = append(op, p(opts))
	}

	return op
}
