package enumeration

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	awsaarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

var errFallbackToCloudControl = errors.New("fallback to cloud control")

// isAccessDeniedError returns true when the error indicates the caller lacks
// permission to perform the requested operation. This is a recoverable
// condition: the region/resource type is skipped with a warning instead of
// aborting the entire enumeration.
func isAccessDeniedError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "AccessDeniedException") ||
		strings.Contains(msg, "AccessDenied") ||
		strings.Contains(msg, "UnauthorizedAccess")
}

// SkippedResource records a resource type + region that was skipped during
// enumeration due to a non-fatal error (access denied, unsupported type, etc.).
type SkippedResource struct {
	ResourceType string
	Region       string
	Reason       string
}

// SkippedTracker collects non-fatal errors encountered during enumeration so
// they can be surfaced to the operator after a run.
type SkippedTracker struct {
	mu      sync.Mutex
	skipped []SkippedResource
}

func (t *SkippedTracker) Record(resourceType, region, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.skipped = append(t.skipped, SkippedResource{
		ResourceType: resourceType,
		Region:       region,
		Reason:       reason,
	})
}

// Skipped returns all recorded skipped resources.
func (t *SkippedTracker) Skipped() []SkippedResource {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]SkippedResource(nil), t.skipped...)
}

// LogSummary logs a summary of all skipped resources. Call after enumeration
// completes so the operator can see what was skipped and why.
func (t *SkippedTracker) LogSummary() {
	skipped := t.Skipped()
	if len(skipped) == 0 {
		return
	}
	for _, s := range skipped {
		slog.Warn("skipped resource", "resource_type", s.ResourceType, "region", s.Region, "reason", s.Reason)
	}
	slog.Warn("enumeration completed with skipped resources — review errors above",
		"total_skipped", len(skipped))
}

// ResourceEnumerator enumerates AWS resources of a specific type.
type ResourceEnumerator interface {
	// ResourceType returns the CloudControl type string, e.g. "AWS::S3::Bucket".
	ResourceType() string

	// EnumerateAll enumerates all resources of this type across configured regions.
	EnumerateAll(out *pipeline.P[output.AWSResource]) error

	// EnumerateByARN fetches a single resource by ARN.
	EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error
}

// Enumerator dispatches resource enumeration to registered ResourceEnumerators,
// falling back to CloudControlEnumerator for unregistered types.
type Enumerator struct {
	enumerators map[string]ResourceEnumerator
	cc          *CloudControlEnumerator
	Skipped     SkippedTracker
}

// NewEnumerator creates an Enumerator with CloudControl fallback and registers
// all built-in resource-specific enumerators.
func NewEnumerator(opts plugin.AWSCommonRecon) *Enumerator {
	provider := NewAWSConfigProvider(opts)
	cc := NewCloudControlEnumeratorWithProvider(opts, provider)
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          cc,
	}
	// Register built-in enumerators here as they are implemented.
	e.Register(NewAmplifyAppEnumerator(opts, provider))
	e.Register(NewS3Enumerator(opts, provider))

	iamEnum := NewIAMEnumerator(opts, provider)
	e.Register(iamEnum.RoleEnumerator())
	e.Register(iamEnum.PolicyEnumerator())
	e.Register(iamEnum.UserEnumerator())

	e.Register(NewEC2ImageEnumerator(opts, provider))
	e.Register(NewSSMDocumentEnumerator(opts, provider))

	return e
}

// Register adds a ResourceEnumerator to the registry.
func (e *Enumerator) Register(l ResourceEnumerator) {
	e.enumerators[l.ResourceType()] = l
}

// List routes an identifier (ARN or resource type) to the appropriate enumerator.
// This has the same signature as CloudControlEnumerator.List for drop-in replacement.
// Errors from individual enumerators are recorded and do not halt the pipeline.
func (e *Enumerator) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		if err := e.listByARN(parsed, identifier, out); err != nil {
			e.Skipped.Record(identifier, "", err.Error())
		}
		return nil
	}

	if strings.HasPrefix(identifier, "AWS::") {
		if err := e.listByType(identifier, out); err != nil {
			e.Skipped.Record(identifier, "", err.Error())
		}
		return nil
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

func (e *Enumerator) listByARN(parsed awsaarn.ARN, rawARN string, out *pipeline.P[output.AWSResource]) error {
	resourceType, ok := types.ResolveResourceType(parsed.Service, parsed.Resource)
	if !ok {
		return e.cc.EnumerateByARN(rawARN, out)
	}

	if enum, ok := e.enumerators[resourceType]; ok {
		err := enum.EnumerateByARN(rawARN, out)
		if errors.Is(err, errFallbackToCloudControl) {
			return e.cc.EnumerateByARN(rawARN, out)
		}
		return err
	}

	return e.cc.EnumerateByARN(rawARN, out)
}

func (e *Enumerator) listByType(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if enum, ok := e.enumerators[resourceType]; ok {
		return enum.EnumerateAll(out)
	}

	return e.cc.EnumerateByType(resourceType, out)
}
