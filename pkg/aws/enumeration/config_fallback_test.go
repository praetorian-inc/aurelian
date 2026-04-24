package enumeration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConfigFallback builds a ConfigFallback with all SDK calls replaced by
// closures under test control.
type fakeConfigFallback struct {
	describeStatus func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error)
	listDiscovered func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error)
	hydrate        func(region, resourceType, identifier string) (output.AWSResource, error)
}

func (f *fakeConfigFallback) build() *ConfigFallback {
	return &ConfigFallback{
		translator:        newConfigIdentifier(),
		describeRecorders: f.describeStatus,
		listDiscovered:    f.listDiscovered,
		hydrate:           f.hydrate,
	}
}

func collectAttempt(t *testing.T, fb *ConfigFallback, resourceType, region string) ([]output.AWSResource, error) {
	t.Helper()
	out := pipeline.New[output.AWSResource]()
	var got []output.AWSResource
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for r := range out.Range() {
			got = append(got, r)
		}
	}()
	err := fb.Attempt(context.Background(), resourceType, region, out)
	out.Close()
	require.NoError(t, out.Wait())
	collectWG.Wait()
	return got, err
}

func accessDenied(msg string) error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: msg}
}

func TestConfigFallback_RecorderProbeAccessDeniedCachesRegionUnavailable(t *testing.T) {
	var calls atomic.Int32
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			calls.Add(1)
			return nil, accessDenied("config denied")
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, int32(1), calls.Load(), "recorder probe must run exactly once per region")
}

func TestConfigFallback_RecorderProbeEmptyCachesRegionUnavailable(t *testing.T) {
	var calls atomic.Int32
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			calls.Add(1)
			return nil, nil // no recorders configured
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, int32(1), calls.Load(), "recorder probe must run exactly once per region")
}

func TestConfigFallback_RecorderProbeTransientErrorDoesNotCache(t *testing.T) {
	var calls atomic.Int32
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			calls.Add(1)
			return nil, errors.New("throttled")
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, int32(2), calls.Load(), "transient errors must not cache the region")
}

func TestConfigFallback_GlobalServiceNormalizesToUSEast1(t *testing.T) {
	var seenRegion string
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			seenRegion = region
			return nil, accessDenied("x")
		},
	}
	fb := f.build()

	_, _ = collectAttempt(t, fb, "AWS::CloudFront::Distribution", "ap-northeast-1")
	assert.Equal(t, "us-east-1", seenRegion, "global service types must normalize region to us-east-1")
}

func TestConfigFallback_RecorderStoppedTreatedAsUnavailable(t *testing.T) {
	var calls atomic.Int32
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			calls.Add(1)
			return []configtypes.ConfigurationRecorderStatus{{Recording: false}}, nil
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)
	assert.ErrorIs(t, err1, errConfigNoRecorder)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, int32(1), calls.Load(), "stopped recorder must be cached as unavailable, probed once")
}

func okStatus() []configtypes.ConfigurationRecorderStatus {
	return []configtypes.ConfigurationRecorderStatus{{Recording: true}}
}

func TestConfigFallback_SuccessEmitsHydratedResources(t *testing.T) {
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			return []configtypes.ResourceIdentifier{
				{ResourceName: aws.String("bucket-a"), ResourceId: aws.String("bucket-a")},
				{ResourceName: aws.String("bucket-b"), ResourceId: aws.String("bucket-b")},
			}, nil
		},
		hydrate: func(region, resourceType, identifier string) (output.AWSResource, error) {
			return output.AWSResource{ResourceType: resourceType, ResourceID: identifier, Region: region}, nil
		},
	}
	fb := f.build()

	got, err := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "bucket-a", got[0].ResourceID)
	assert.Equal(t, "bucket-b", got[1].ResourceID)
}

func TestConfigFallback_EmptyListExhaustsTypeWithoutPoisoningRegion(t *testing.T) {
	listCalls := 0
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			listCalls++
			return nil, nil
		},
		hydrate: func(region, resourceType, identifier string) (output.AWSResource, error) {
			return output.AWSResource{}, errors.New("should not be called")
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)
	assert.ErrorIs(t, err1, errConfigNoRecords, "empty list must wrap errConfigNoRecords")

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, 2, listCalls, "empty list must not cache the region; each type re-probes")
}

func TestConfigFallback_ListAccessDeniedCachesRegionUnavailable(t *testing.T) {
	listCalls := 0
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			listCalls++
			return nil, accessDenied("list denied")
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, 1, listCalls, "list AccessDenied is region-wide; subsequent types short-circuit")
}

func TestConfigFallback_AllHydrationFailsTransitionsToHydrationBlocked(t *testing.T) {
	hydrateCalls := 0
	listCalls := 0
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			listCalls++
			return []configtypes.ResourceIdentifier{
				{ResourceName: aws.String("x")}, {ResourceName: aws.String("y")},
			}, nil
		},
		hydrate: func(region, resourceType, identifier string) (output.AWSResource, error) {
			hydrateCalls++
			return output.AWSResource{}, accessDenied("get denied")
		},
	}
	fb := f.build()

	_, err1 := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.ErrorIs(t, err1, errFallbackExhausted)

	_, err2 := collectAttempt(t, fb, "AWS::Amplify::App", "us-east-1")
	assert.ErrorIs(t, err2, errFallbackExhausted)

	assert.Equal(t, 1, listCalls, "hydrationBlocked short-circuits subsequent types at step 2")
	assert.Equal(t, 2, hydrateCalls, "only the first type hydrates")
}

func TestConfigFallback_PartialHydrationStillSucceeds(t *testing.T) {
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			return []configtypes.ResourceIdentifier{
				{ResourceName: aws.String("ok")},
				{ResourceName: aws.String("broken")},
			}, nil
		},
		hydrate: func(region, resourceType, identifier string) (output.AWSResource, error) {
			if identifier == "broken" {
				return output.AWSResource{}, errors.New("not found")
			}
			return output.AWSResource{ResourceType: resourceType, ResourceID: identifier, Region: region}, nil
		},
	}
	fb := f.build()

	got, err := collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
	assert.NoError(t, err, "≥1 successful emission means not exhausted")
	require.Len(t, got, 1)
	assert.Equal(t, "ok", got[0].ResourceID)
}

func TestConfigFallback_ConcurrentCallsProbeOnce(t *testing.T) {
	var probeCalls atomic.Int32
	f := &fakeConfigFallback{
		describeStatus: func(ctx context.Context, region string) ([]configtypes.ConfigurationRecorderStatus, error) {
			probeCalls.Add(1)
			return okStatus(), nil
		},
		listDiscovered: func(ctx context.Context, region, resourceType string) ([]configtypes.ResourceIdentifier, error) {
			return []configtypes.ResourceIdentifier{{ResourceName: aws.String("x")}}, nil
		},
		hydrate: func(region, resourceType, identifier string) (output.AWSResource, error) {
			return output.AWSResource{ResourceType: resourceType, ResourceID: identifier}, nil
		},
	}
	fb := f.build()

	var wg sync.WaitGroup
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = collectAttempt(t, fb, "AWS::S3::Bucket", "us-east-1")
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), probeCalls.Load(), "30 concurrent callers must trigger exactly one recorder probe")
}
