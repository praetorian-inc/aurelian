package enumeration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// errConfigNoRecorder is the cached reason when DescribeConfigurationRecorderStatus
// returns no recorders for the region.
var errConfigNoRecorder = errors.New("no config recorder in region")

// errConfigNoRecords is the reason returned when the recorder is up but
// ListDiscoveredResources returned zero records for this (type, region). This
// does NOT poison the region cache; only this (type, region) pair is marked
// exhausted.
var errConfigNoRecords = errors.New("no config records for resource type in region")

// errHydrationBlocked is the cached reason when Config listed records but every
// CloudControl GetResource call for them failed. Indicates the region is
// unusable for the rest of the run.
var errHydrationBlocked = errors.New("cloudcontrol get denied in region")

type regionState int

const (
	regionUnknown regionState = iota
	regionAvailable
	regionUnavailable
	regionHydrationBlocked
)

type regionStateEntry struct {
	mu      sync.Mutex
	state   regionState
	reason  error
	logOnce sync.Once
}

// ConfigFallback wraps AWS Config ListDiscoveredResources + CloudControl
// GetResource to restore visibility when a primary list call is denied by an
// SCP or IAM policy. Callers invoke Attempt from within a fallback closure
// passed to handleListError.
type ConfigFallback struct {
	provider   *AWSConfigProvider
	cc         *CloudControlEnumerator
	translator *configIdentifier
	regions    sync.Map // map[string]*regionStateEntry

	// Test seams; production callers leave these nil and the real SDK paths
	// run via the provider + cc fields.
	describeRecorders func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error)
	listDiscovered    func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error)
	hydrate           func(region, resourceType, identifier string) (output.AWSResource, error)
}

// NewConfigFallback constructs a ConfigFallback that shares provider and
// CloudControl state with the rest of the enumerator pipeline.
func NewConfigFallback(provider *AWSConfigProvider, cc *CloudControlEnumerator) *ConfigFallback {
	return &ConfigFallback{
		provider:   provider,
		cc:         cc,
		translator: newConfigIdentifier(),
	}
}

// Attempt runs the Config fallback for the given resource type in the given
// region, emitting hydrated resources into out. Returns nil on at least one
// successful emission; errFallbackExhausted otherwise.
func (f *ConfigFallback) Attempt(
	ctx context.Context,
	resourceType, region string,
	out *pipeline.P[output.AWSResource],
) error {
	if awshelpers.IsGlobalService(resourceType) {
		region = "us-east-1"
	}

	if entry, ok := f.regions.Load(region); ok {
		e := entry.(*regionStateEntry)
		e.mu.Lock()
		state, reason := e.state, e.reason
		e.mu.Unlock()
		if state == regionUnavailable || state == regionHydrationBlocked {
			return fmt.Errorf("%w: %w", errFallbackExhausted, reason)
		}
	}

	entryVal, _ := f.regions.LoadOrStore(region, &regionStateEntry{})
	entry := entryVal.(*regionStateEntry)

	if err := f.ensureRegionProbed(ctx, region, entry); err != nil {
		return err
	}

	return f.listAndHydrate(ctx, resourceType, region, entry, out)
}

// ensureRegionProbed runs DescribeConfigurationRecorderStatus exactly once per
// region per run and caches the outcome. Concurrent callers for the same region
// serialize on entry.mu; only the first one probes.
func (f *ConfigFallback) ensureRegionProbed(
	ctx context.Context,
	region string,
	entry *regionStateEntry,
) error {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.state == regionAvailable {
		return nil
	}
	if entry.state == regionUnavailable || entry.state == regionHydrationBlocked {
		return fmt.Errorf("%w: %w", errFallbackExhausted, entry.reason)
	}

	statuses, err := f.describeRecorderStatus(ctx, region)
	switch {
	case err == nil && !hasActiveRecorder(statuses):
		entry.state = regionUnavailable
		entry.reason = errConfigNoRecorder
		entry.logOnce.Do(func() {
			slog.Info("config recorder unavailable in region",
				"region", region, "reason", errConfigNoRecorder.Error())
		})
		return fmt.Errorf("%w: %w", errFallbackExhausted, errConfigNoRecorder)
	case err == nil:
		entry.state = regionAvailable
		return nil
	case isAccessDeniedError(err):
		entry.state = regionUnavailable
		entry.reason = err
		entry.logOnce.Do(func() {
			slog.Info("config recorder unavailable in region",
				"region", region, "reason", err.Error())
		})
		return fmt.Errorf("%w: %w", errFallbackExhausted, err)
	default:
		// Transient; do not cache.
		return fmt.Errorf("%w: describe recorder status: %w", errFallbackExhausted, err)
	}
}

func (f *ConfigFallback) describeRecorderStatus(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
	if f.describeRecorders != nil {
		return f.describeRecorders(ctx, region)
	}
	cfg, err := f.provider.GetAWSConfig(region)
	if err != nil {
		return nil, fmt.Errorf("get aws config for %s: %w", region, err)
	}
	client := configservice.NewFromConfig(*cfg)
	resp, err := client.DescribeConfigurationRecorderStatus(ctx,
		&configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, err
	}
	return resp.ConfigurationRecordersStatus, nil
}

// listAndHydrate is implemented in Task 10.
func (f *ConfigFallback) listAndHydrate(
	ctx context.Context,
	resourceType, region string,
	entry *regionStateEntry,
	out *pipeline.P[output.AWSResource],
) error {
	return fmt.Errorf("%w: not yet implemented", errFallbackExhausted)
}

// hasActiveRecorder reports whether at least one recorder in statuses is
// actively recording. A recorder that exists but is stopped yields stale
// ListDiscoveredResources results and is treated the same as no recorder.
func hasActiveRecorder(statuses []configtypes.ConfigurationRecorderStatus) bool {
	for _, s := range statuses {
		if s.Recording {
			return true
		}
	}
	return false
}
