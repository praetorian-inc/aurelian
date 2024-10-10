package modules

import (
	"sync"

	"github.com/praetorian-inc/nebula/modules/options"
)

type OutputProvider interface {
	Write(result Result) error
}

type OutputProviders []func(options []*options.Option) OutputProvider

type OpsecLevel string

const (
	Stealth  OpsecLevel = "stealth"
	Moderate OpsecLevel = "moderate"
	None     OpsecLevel = "none"
)

type Platform string

func GetPlatformFromString(platform string) Platform {
	switch platform {
	case "aws":
		return AWS
	case "azure":
		return Azure
	case "gcp":
		return GCP
	case "oci":
		return OCI
	case "universal":
		return Universal
	default:
		return ""
	}
}

const (
	AWS       Platform = "aws"
	Azure     Platform = "azure"
	GCP       Platform = "gcp"
	OCI       Platform = "oci"
	Universal Platform = "universal"
)

type Metadata struct {
	Id          string
	Name        string
	Description string
	Platform    Platform
	Authors     []string
	References  []string
	OpsecLevel  OpsecLevel
}

type Module interface {
	Invoke() error
	GetOutputProviders() []OutputProvider
}

type BaseModule struct {
	Module
	Metadata
	Options         []*options.Option
	OutputProviders []OutputProvider
	Run             Run
}

func (m *BaseModule) Invoke() error {
	panic("not implemented")
}

func (m *BaseModule) GetOptionByName(name string) *options.Option {
	return options.GetOptionByName(name, m.Options)
}

func (m *BaseModule) AddOption(option options.Option) {
	m.Options = append(m.Options, &option)
}

func (m *BaseModule) SetMetdata(meta Metadata) {
	m.Id = meta.Id
	m.Name = meta.Name
	m.Description = meta.Description
	m.Platform = meta.Platform
	m.Authors = meta.Authors
	m.References = meta.References
	m.OpsecLevel = meta.OpsecLevel
}

func (m *BaseModule) MakeResult(data interface{}, opts ...ResultOption) Result {
	return NewResult(m.Platform, m.Name, data, opts...)
}

func (m *BaseModule) GetOutputProviders() []OutputProvider {
	return m.OutputProviders
}

func (m *BaseModule) ConfigureOutputProviders(providers []func(options []*options.Option) OutputProvider) {
	for _, p := range providers {
		m.OutputProviders = append(m.OutputProviders, p(m.Options))
	}
}

func RenderOutputProviders(providers []func(options []*options.Option) OutputProvider, opts []*options.Option) []OutputProvider {
	op := []OutputProvider{}
	for _, p := range providers {
		op = append(op, p(opts))
	}

	return op
}

func RunModule(factoryFn func(options []*options.Option, run Run) (Module, error), options []*options.Option, run Run) error {

	var err error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m Module

		m, err := factoryFn(options, run)
		if err == nil {
			err = m.Invoke()
		}
	}()

	wg.Wait()
	if err != nil {
		return err
	}

	return nil
}
