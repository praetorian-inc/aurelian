package imageconfig

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fake replaces the registry round trip. Its network path is covered against
// real ECR and real Docker Hub by the AWS integration test; what is faked here
// is only the transport, so the caching, bounding and fail-soft rules can be
// asserted without one.
type fake struct {
	mu      sync.Mutex
	calls   int
	byRef   map[string]*v1.ConfigFile
	digests map[string]string
	err     error
}

func (f *fake) get(_ context.Context, ref string, _ authn.Authenticator) (*v1.ConfigFile, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, "", f.err
	}
	cf, ok := f.byRef[ref]
	if !ok {
		return nil, "", errors.New("not found")
	}
	return cf, f.digests[ref], nil
}

func cfgFile(env, entrypoint, cmd []string) *v1.ConfigFile {
	return &v1.ConfigFile{Config: v1.Config{Env: env, Entrypoint: entrypoint, Cmd: cmd}}
}

func TestFetch_ReturnsEnvEntrypointAndCmd(t *testing.T) {
	f := &fake{
		byRef:   map[string]*v1.ConfigFile{"nginx:1.25": cfgFile([]string{"NGINX_VERSION=1.25.5", "PATH=/usr/bin"}, []string{"/docker-entrypoint.sh"}, []string{"nginx", "-g", "daemon off;"})},
		digests: map[string]string{"nginx:1.25": "sha256:aaa"},
	}
	got := New(f.get).Fetch(t.Context(), "nginx:1.25", nil)

	assert.Equal(t, "nginx:1.25", got.Ref)
	assert.Equal(t, "sha256:aaa", got.Digest)
	assert.Equal(t, []string{"NGINX_VERSION=1.25.5", "PATH=/usr/bin"}, got.Env)
	assert.Equal(t, []string{"/docker-entrypoint.sh"}, got.Entrypoint)
	assert.Equal(t, []string{"nginx", "-g", "daemon off;"}, got.Cmd)
}

func TestFetch_SameReferenceIsFetchedOnce(t *testing.T) {
	// Fifty task definitions referencing one image are one fetch. Config
	// content is a pure function of the digest.
	f := &fake{
		byRef:   map[string]*v1.ConfigFile{"app:1": cfgFile([]string{"PYTHON_VERSION=3.11.18"}, nil, nil)},
		digests: map[string]string{"app:1": "sha256:bbb"},
	}
	fetcher := New(f.get)
	for range 50 {
		require.Equal(t, "sha256:bbb", fetcher.Fetch(t.Context(), "app:1", nil).Digest)
	}
	assert.Equal(t, 1, f.calls)
}

func TestFetch_ConcurrentCallersForOneReferenceFetchOnce(t *testing.T) {
	// The enricher runs inside a shared concurrent pipeline stage, so several
	// workers reach the same reference at once.
	f := &fake{
		byRef:   map[string]*v1.ConfigFile{"app:1": cfgFile([]string{"RUBY_VERSION=3.3.14"}, nil, nil)},
		digests: map[string]string{"app:1": "sha256:ccc"},
	}
	fetcher := New(f.get)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			fetcher.Fetch(t.Context(), "app:1", nil)
		})
	}
	wg.Wait()
	assert.Equal(t, 1, f.calls, "concurrent callers must share one fetch, not race into several")
}

func TestFetch_FailureYieldsEmptyConfigAndIsNotRetried(t *testing.T) {
	// An image that cannot be pulled contributes nothing and must never fail
	// the module. Re-fetching a known-bad reference on every resource that
	// names it would turn one unreachable image into a scan-long stall.
	f := &fake{err: errors.New("denied")}
	fetcher := New(f.get)
	for range 10 {
		got := fetcher.Fetch(t.Context(), "private/app:1", nil)
		assert.True(t, got.Empty())
	}
	assert.Equal(t, 1, f.calls)
}

func TestFetch_EmptyReferenceMakesNoCall(t *testing.T) {
	f := &fake{}
	assert.True(t, New(f.get).Fetch(t.Context(), "", nil).Empty())
	assert.Equal(t, 0, f.calls)
}

func TestFetch_BoundsHostileEnvironments(t *testing.T) {
	// Layer and config content is attacker-controlled. A registry that returns
	// ten thousand env entries, or one env value a megabyte long, must not
	// become this process's memory profile.
	var many []string
	for i := range 10_000 {
		many = append(many, "K"+strings.Repeat("x", 3)+"=v"+string(rune('a'+i%26)))
	}
	many = append(many, "HUGE="+strings.Repeat("z", 1<<20))

	f := &fake{
		byRef:   map[string]*v1.ConfigFile{"hostile:1": cfgFile(many, nil, nil)},
		digests: map[string]string{"hostile:1": "sha256:ddd"},
	}
	got := New(f.get).Fetch(t.Context(), "hostile:1", nil)

	assert.LessOrEqual(t, len(got.Env), MaxEnvEntries)
	for _, e := range got.Env {
		assert.LessOrEqual(t, len(e), MaxEnvEntryLength, "entry %q", e[:min(40, len(e))])
	}
}

func TestFetch_BoundsEntrypointAndCmd(t *testing.T) {
	var many []string
	for range 5_000 {
		many = append(many, "arg")
	}
	f := &fake{
		byRef:   map[string]*v1.ConfigFile{"hostile:2": cfgFile(nil, many, many)},
		digests: map[string]string{"hostile:2": "sha256:eee"},
	}
	got := New(f.get).Fetch(t.Context(), "hostile:2", nil)
	assert.LessOrEqual(t, len(got.Entrypoint), MaxArgs)
	assert.LessOrEqual(t, len(got.Cmd), MaxArgs)
}

func TestConfig_EmptyIsTrueOnlyWhenNothingWasObserved(t *testing.T) {
	assert.True(t, Config{}.Empty())
	assert.True(t, Config{Ref: "app:1"}.Empty(), "a reference alone is not an observation")
	assert.False(t, Config{Env: []string{"A=b"}}.Empty())
	assert.False(t, Config{Cmd: []string{"nginx"}}.Empty())
	assert.False(t, Config{Entrypoint: []string{"sh"}}.Empty())
}
