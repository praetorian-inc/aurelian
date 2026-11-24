// Package imageconfig fetches the OCI image config blob for an image
// reference — the few kilobytes of JSON that carry a container's environment,
// entrypoint and command.
//
// It exists so that the primary stack an image runs can be identified without
// pulling a single layer. Official images set a version marker in their
// environment as a matter of convention, and that marker is inherited by every
// image built FROM them, so a private `myorg/app` built on `python:3.11`
// announces its runtime in a blob the registry serves before any layer moves.
// See pkg/software/testdata/imageconfig/FINDINGS.md for the harvested evidence.
//
// This package performs network I/O, which is why it is separate from
// pkg/software: software.Detect is a pure function of (resourceType,
// properties) and stays that way. The fetch happens in an enricher, which
// hands the resulting Config to a pure decoder.
package imageconfig

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Bounds on what is retained from a config blob. A registry is not trusted
// infrastructure: the blob is attacker-controlled by whoever can push to the
// repository, and an image that pins fifty thousand environment entries or one
// entry a megabyte long must not become this process's memory profile. Real
// images are far under every one of these — the largest harvested config is
// 18 KB in total.
const (
	MaxEnvEntries     = 512
	MaxEnvEntryLength = 1024
	MaxArgs           = 128
)

// DefaultTimeout bounds one registry round trip. A registry that accepts the
// connection and then stalls must not hold a pipeline worker open.
const DefaultTimeout = 20 * time.Second

// Config is the part of an image config blob that identifies a stack.
//
// It is a plain value with no registry types in it, so the decoder that
// consumes it stays pure and table-testable.
type Config struct {
	// Ref is the reference as it was requested, for Evidence.
	Ref string
	// Digest is the resolved image digest. Retained even when nothing else is:
	// it is what makes an emission reproducible and what keys the cache.
	Digest string

	Env        []string
	Entrypoint []string
	Cmd        []string
}

// Empty reports whether the fetch observed nothing usable. A reference or a
// digest alone is not an observation — a technology can only come from Env,
// Entrypoint or Cmd.
func (c Config) Empty() bool {
	return len(c.Env) == 0 && len(c.Entrypoint) == 0 && len(c.Cmd) == 0
}

// GetFunc is the registry round trip. It is a field rather than a direct call
// so the caching, bounding and fail-soft rules can be tested without a
// network; the real path is exercised against live ECR and live Docker Hub by
// the AWS integration test.
type GetFunc func(ctx context.Context, ref string, auth authn.Authenticator) (*v1.ConfigFile, string, error)

// Fetcher fetches image configs, at most once per reference for its lifetime.
//
// Safe for concurrent use: it is held by an enricher that runs inside the
// shared concurrent pipeline stage, so several workers reach the same
// reference at once and must not race into several fetches of it.
type Fetcher struct {
	get GetFunc

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	once sync.Once
	cfg  Config
}

// New returns a Fetcher using get for the registry round trip. Pass nil for
// the real one.
func New(get GetFunc) *Fetcher {
	if get == nil {
		get = RemoteGet
	}
	return &Fetcher{get: get, cache: map[string]*entry{}}
}

// Fetch returns the config for ref, or a zero Config if it cannot be had.
//
// It never returns an error. An image that cannot be pulled — withdrawn,
// denied, rate-limited, malformed, unreachable — contributes no technology and
// is logged at debug. The caller is an enricher on a scan path; a registry it
// cannot read is not a reason to fail a module.
//
// A failed reference is cached as failed. Re-fetching a known-bad image once
// per resource that names it would turn one unreachable reference into a
// scan-long stall.
func (f *Fetcher) Fetch(ctx context.Context, ref string, auth authn.Authenticator) Config {
	if ref == "" {
		return Config{}
	}

	f.mu.Lock()
	e, ok := f.cache[ref]
	if !ok {
		e = &entry{}
		f.cache[ref] = e
	}
	f.mu.Unlock()

	e.once.Do(func() {
		e.cfg = f.fetchOnce(ctx, ref, auth)
	})
	return e.cfg
}

func (f *Fetcher) fetchOnce(ctx context.Context, ref string, auth authn.Authenticator) Config {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	cf, digest, err := f.get(ctx, ref, auth)
	if err != nil {
		slog.Debug("image config fetch failed", "ref", ref, "error", err)
		return Config{}
	}
	if cf == nil {
		return Config{}
	}

	return Config{
		Ref:        ref,
		Digest:     digest,
		Env:        boundEntries(cf.Config.Env, MaxEnvEntries, MaxEnvEntryLength),
		Entrypoint: boundEntries(cf.Config.Entrypoint, MaxArgs, MaxEnvEntryLength),
		Cmd:        boundEntries(cf.Config.Cmd, MaxArgs, MaxEnvEntryLength),
	}
}

// boundEntries keeps at most maxEntries values, dropping any longer than
// maxLength. Over-long values are dropped rather than truncated: a truncated
// version string is a confidently wrong version, which is the one output this
// design forbids.
func boundEntries(in []string, maxEntries, maxLength int) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(in), maxEntries))
	for _, v := range in {
		if len(out) == maxEntries {
			break
		}
		if len(v) > maxLength {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RemoteGet is the real registry round trip: resolve the reference, read the
// manifest, read the config blob. It never calls Layers, which is the whole
// cost argument for this package.
func RemoteGet(ctx context.Context, ref string, auth authn.Authenticator) (*v1.ConfigFile, string, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", err
	}

	opts := []remote.Option{remote.WithContext(ctx)}
	if auth != nil {
		opts = append(opts, remote.WithAuth(auth))
	} else {
		// Public registries are reached anonymously. The keychain picks up an
		// ambient docker login when the operator has one.
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	img, err := remote.Image(parsed, opts...)
	if err != nil {
		return nil, "", err
	}

	var digest string
	if d, err := img.Digest(); err == nil {
		digest = d.String()
	}

	cf, err := img.ConfigFile()
	if err != nil {
		return nil, digest, err
	}
	return cf, digest, nil
}
