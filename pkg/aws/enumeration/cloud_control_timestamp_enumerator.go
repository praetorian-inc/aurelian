package enumeration

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// stampFunc sets LastModified on a resource from a native API. It returns an
// error only when AWS omits a field its API contract guarantees; call failures
// are recorded (see recordTimestampFailure) and leave LastModified nil so the
// resource is still emitted and scanned.
type stampFunc func(r *output.AWSResource) error

// lastModifiedSource supplies stampers for a CloudControl-listed type.
// regionStamper may prefetch region-wide data once per EnumerateAll region;
// resourceStamper serves the single-resource EnumerateByARN path.
type lastModifiedSource interface {
	regionStamper(region string) stampFunc
	resourceStamper(region string) stampFunc
}

// CloudControlTimestampEnumerator lists a type through CloudControl and adds
// LastModified from native APIs. Guard keys assets by ARN and stores Properties
// verbatim, and extractors read CloudControl identifiers, so everything except
// LastModified must stay exactly what CloudControl emits.
type CloudControlTimestampEnumerator struct {
	cc           *CloudControlEnumerator
	resourceType string
	source       lastModifiedSource
}

func newCloudControlTimestampEnumerator(cc *CloudControlEnumerator, resourceType string, source lastModifiedSource) *CloudControlTimestampEnumerator {
	return &CloudControlTimestampEnumerator{cc: cc, resourceType: resourceType, source: source}
}

func (e *CloudControlTimestampEnumerator) ResourceType() string {
	return e.resourceType
}

func (e *CloudControlTimestampEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.cc.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	actor := ratelimit.NewCrossRegionActor(e.cc.Concurrency)
	return actor.ActInRegions(e.cc.Regions, func(region string) error {
		return e.listAndStamp(func(p *pipeline.P[output.AWSResource]) error {
			return e.cc.listInRegionByType(region, e.resourceType, p)
		}, e.source.regionStamper(region), out)
	})
}

func (e *CloudControlTimestampEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	region, _, _, err := e.cc.resolveARNTarget(arn)
	if err != nil {
		return err
	}
	return e.listAndStamp(func(p *pipeline.P[output.AWSResource]) error {
		return e.cc.EnumerateByARN(arn, p)
	}, e.source.resourceStamper(region), out)
}

// listAndStamp streams list's output through stamp into out. A resource whose
// stamp fails is withheld rather than sent with a guessed time; the rest are
// still emitted and the failures are returned together.
func (e *CloudControlTimestampEnumerator) listAndStamp(list func(*pipeline.P[output.AWSResource]) error, stamp stampFunc, out *pipeline.P[output.AWSResource]) error {
	listed := pipeline.New[output.AWSResource]()
	go func() { listed.CloseWithError(list(listed)) }()

	var stampErrs []error
	for r := range listed.Range() {
		if err := stamp(&r); err != nil {
			stampErrs = append(stampErrs, err)
			continue
		}
		out.Send(r)
	}
	return errors.Join(append(stampErrs, listed.Wait())...)
}

// warnTimestampFailure logs a timestamp call failure that ClassifySkippable
// did not claim. The caller leaves LastModified nil so the resource is still
// emitted and always scanned.
func warnTimestampFailure(err error, service, operation, region, resource string) {
	slog.Warn("failed to read last-modified time; resource will always be scanned",
		"service", service, "operation", operation, "region", region, "resource", resource, "error", err)
}
