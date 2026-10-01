package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// stampFunc sets LastModified on a resource from a native API. It returns an
// error, naming the field, only when AWS omits a field its API contract
// guarantees; call failures are recorded (skip report or logTimestampFailure)
// and leave LastModified nil so the resource is still emitted and scanned.
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

// listAndStamp streams list's output through stamp into out. A failed stamp
// affects only its resource: it is logged and the resource is still emitted
// with LastModified nil (always scanned), never a guessed time. Only list's
// own error is returned.
func (e *CloudControlTimestampEnumerator) listAndStamp(list func(*pipeline.P[output.AWSResource]) error, stamp stampFunc, out *pipeline.P[output.AWSResource]) error {
	listed := pipeline.New[output.AWSResource]()
	go func() { listed.CloseWithError(list(listed)) }()

	for r := range listed.Range() {
		if err := stamp(&r); err != nil {
			r.LastModified = nil
			logTimestampFailure(slog.LevelError, err, "", "", r.Region, &r)
		}
		out.Send(r)
	}
	return listed.Wait()
}

// logTimestampFailure is the single log line for every LastModified failure,
// so each carries the same fields. Missing contracted fields log at Error;
// call failures ClassifySkippable did not claim log at Warn. service and
// operation are empty when the error text already names them; r is nil for a
// region-wide call. The caller leaves LastModified nil so affected resources
// are still emitted and always scanned.
func logTimestampFailure(level slog.Level, err error, service, operation, region string, r *output.AWSResource) {
	var resourceType, resourceID, arn string
	if r != nil {
		resourceType, resourceID, arn = r.ResourceType, r.ResourceID, r.ARN
	}
	slog.Log(context.Background(), level, "failed to read last-modified time; resource will always be scanned",
		"resource_type", resourceType, "resource_id", resourceID, "arn", arn, "region", region,
		"service", service, "operation", operation, "error", err)
}
