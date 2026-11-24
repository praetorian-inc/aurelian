package plugin

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSRequestHook_BoundAndClearedPerRun(t *testing.T) {
	mod := &requestHookModule{}
	wrapped := ModuleWrapper{Module: mod}
	calls := 0
	cfg := Config{
		Args:             map[string]any{"regions": []string{"us-east-1"}},
		AWSBeforeRequest: func(context.Context) error { calls++; return nil },
	}
	out := pipeline.New[model.AurelianModel]()
	defer out.Close()

	require.NoError(t, wrapped.Run(cfg, out))
	require.NotNil(t, mod.params.BeforeRequest)
	require.NoError(t, mod.params.BeforeRequest(context.Background()))
	assert.Equal(t, 1, calls)

	cfg.AWSBeforeRequest = nil
	require.NoError(t, wrapped.Run(cfg, out))
	assert.Nil(t, mod.params.BeforeRequest)
}

func TestModuleWrapper_NewInstanceIsolatesRequestHooks(t *testing.T) {
	prototype := &ModuleWrapper{Module: &requestHookModule{}}
	first, err := prototype.NewInstance()
	require.NoError(t, err)
	second, err := prototype.NewInstance()
	require.NoError(t, err)
	firstCalls, secondCalls := 0, 0
	out := pipeline.New[model.AurelianModel]()
	defer out.Close()
	args := map[string]any{"regions": []string{"us-east-1"}}
	require.NoError(t, first.Run(Config{Args: args, AWSBeforeRequest: func(context.Context) error { firstCalls++; return nil }}, out))
	require.NoError(t, second.Run(Config{Args: args, AWSBeforeRequest: func(context.Context) error { secondCalls++; return nil }}, out))

	require.NoError(t, first.Module.(*requestHookModule).params.BeforeRequest(context.Background()))
	assert.Equal(t, 1, firstCalls)
	assert.Zero(t, secondCalls)
	assert.Nil(t, prototype.Module.(*requestHookModule).params.BeforeRequest)
}

type requestHookModule struct {
	Module
	params AWSCommonRecon
}

func (m *requestHookModule) Parameters() any                                    { return &m.params }
func (m *requestHookModule) Run(Config, *pipeline.P[model.AurelianModel]) error { return nil }
