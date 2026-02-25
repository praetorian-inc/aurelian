package testutils

import (
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// MockModule is a test implementation of plugin.Module.
type MockModule struct {
	IDValue                     string
	NameValue                   string
	DescriptionValue            string
	PlatformValue               plugin.Platform
	CategoryValue               plugin.Category
	OpsecLevelValue             string
	AuthorsValue                []string
	ReferencesValue             []string
	ParametersValue             any
	SupportedResourceTypesValue []string
	RunFn                       func(plugin.Config, *pipeline.P[model.AurelianModel]) error
}

func (m *MockModule) ID() string                { return m.IDValue }
func (m *MockModule) Name() string              { return m.NameValue }
func (m *MockModule) Description() string       { return m.DescriptionValue }
func (m *MockModule) Platform() plugin.Platform { return m.PlatformValue }
func (m *MockModule) Category() plugin.Category { return m.CategoryValue }
func (m *MockModule) OpsecLevel() string {
	if m.OpsecLevelValue == "" {
		return "low"
	}
	return m.OpsecLevelValue
}
func (m *MockModule) Authors() []string    { return m.AuthorsValue }
func (m *MockModule) References() []string { return m.ReferencesValue }
func (m *MockModule) Parameters() any      { return m.ParametersValue }
func (m *MockModule) SupportedResourceTypes() []string {
	return m.SupportedResourceTypesValue
}
func (m *MockModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	if m.RunFn != nil {
		return m.RunFn(cfg, out)
	}
	out.Send(model.BaseAurelianModel{})
	return nil
}
