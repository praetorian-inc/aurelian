package enumeration

import (
	"sync"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
)

type mockLister struct {
	resourceTypes        []string
	listFunc             func(string, *pipeline.P[output.GCPResource]) error
	listByResourceIDFunc func(ResourceIDInput, *pipeline.P[output.GCPResource]) error
}

func (m *mockLister) ResourceTypes() []string { return m.resourceTypes }
func (m *mockLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	if m.listFunc != nil {
		return m.listFunc(projectID, out)
	}
	return nil
}
func (m *mockLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	if m.listByResourceIDFunc != nil {
		return m.listByResourceIDFunc(input, out)
	}
	return nil
}

func TestEnumerator_ForTypes_Filters(t *testing.T) {
	e := &Enumerator{
		listers: []ResourceLister{
			&mockLister{resourceTypes: []string{"type-a"}},
			&mockLister{resourceTypes: []string{"type-b"}},
			&mockLister{resourceTypes: []string{"type-c"}},
		},
		concurrency: 2,
	}

	filtered := e.ForTypes([]string{"type-a", "type-c"})
	assert.Len(t, filtered.listers, 2)
	assert.Equal(t, []string{"type-a"}, filtered.listers[0].ResourceTypes())
	assert.Equal(t, []string{"type-c"}, filtered.listers[1].ResourceTypes())
}

func TestEnumerator_ListForProject_CallsAllListers(t *testing.T) {
	var mu sync.Mutex
	called := make(map[string]bool)
	e := &Enumerator{
		listers: []ResourceLister{
			&mockLister{
				resourceTypes: []string{"type-a"},
				listFunc: func(pid string, out *pipeline.P[output.GCPResource]) error {
					mu.Lock()
					called["type-a"] = true
					mu.Unlock()
					assert.Equal(t, "my-project", pid)
					return nil
				},
			},
			&mockLister{
				resourceTypes: []string{"type-b"},
				listFunc: func(pid string, out *pipeline.P[output.GCPResource]) error {
					mu.Lock()
					called["type-b"] = true
					mu.Unlock()
					return nil
				},
			},
		},
		concurrency: 2,
	}

	out := pipeline.New[output.GCPResource]()
	go func() {
		defer out.Close()
		err := e.ListForProject("my-project", out)
		assert.NoError(t, err)
	}()
	for range out.Range() {
	}

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, called["type-a"])
	assert.True(t, called["type-b"])
}
