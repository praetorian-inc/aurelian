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
	Skipped     *SkipReport
	// ownsSkipReport is true only when this Enumerator created its own SkipReport
	// (via NewEnumerator). When false, the SkipReport is shared with the caller,
	// which owns logging the aggregated summary, so Close skips the summary log to
	// avoid double-logging.
	ownsSkipReport bool
	outputDir      string
	closeOnce      sync.Once
}

// NewEnumerator creates an Enumerator with CloudControl fallback and registers
// all built-in resource-specific enumerators. It owns a fresh AWSConfigProvider
// and SkipReport; callers that want to share those with other enumerators (so
// one aggregated skip summary covers every path) should use
// NewEnumeratorWithProvider instead.
func NewEnumerator(opts plugin.AWSCommonRecon) *Enumerator {
	e := NewEnumeratorWithProvider(opts, NewAWSConfigProvider(opts), NewSkipReport())
	e.ownsSkipReport = true
	return e
}

// NewEnumeratorWithProvider creates an Enumerator that shares the given
// AWSConfigProvider and SkipReport with its caller (and any sibling
// enumerators). Both are safe for concurrent use, so a single provider reuses
// one SDK config cache and a single SkipReport surfaces every skipped
// (region, service) pair across all enumerators in one Summary().
//
// When the SkipReport is shared, the owner is responsible for logging the
// summary exactly once (see Enumerator.Close, which logs only when it created
// the report). Mirrors NewCloudControlEnumeratorWithProvider.
func NewEnumeratorWithProvider(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *Enumerator {
	cc := NewCloudControlEnumeratorWithProvider(opts, provider, skipReport)
	e := &Enumerator{
		enumerators: make(map[string]ResourceEnumerator),
		cc:          cc,
		Skipped:     skipReport,
		outputDir:   opts.OutputDir,
	}
	// Register built-in enumerators here as they are implemented.
	e.Register(NewAmplifyAppEnumerator(opts, provider, skipReport))
	e.Register(NewS3Enumerator(opts, provider, skipReport))

	iamEnum := NewIAMEnumerator(opts, provider, skipReport)
	e.Register(iamEnum.RoleEnumerator())
	e.Register(iamEnum.PolicyEnumerator())
	e.Register(iamEnum.UserEnumerator())

	e.Register(NewEC2ImageEnumerator(opts, provider, skipReport))
	e.Register(NewSSMDocumentEnumerator(opts, provider, skipReport))
	e.Register(NewSSMParameterEnumerator(opts, provider, skipReport))

	return e
}

// Close logs the skip summary and writes the full detail file exactly once.
// Safe to call multiple times; use defer after NewEnumerator so the operator
// always sees which (region, service) pairs were skipped, even on early-return
// error paths.
//
// The summary is logged at Warn (always visible), but only when this Enumerator
// owns its SkipReport (NewEnumerator). When the report is shared
// (NewEnumeratorWithProvider), the caller owns logging the single aggregated
// summary, so Close logs nothing and only writes the detail file. The detail
// file (enumeration-skips.json) is written to OutputDir for post-run analysis.
//
// TestNewEnumeratorRequiresClose enforces via AST analysis that every
// non-test caller of NewEnumerator has a matching defer …Close().
func (e *Enumerator) Close() error {
	e.closeOnce.Do(func() {
		if e.ownsSkipReport {
			e.Skipped.LogSummary()
		}
		if e.outputDir != "" {
			if err := e.Skipped.WriteDetailFile(e.outputDir); err != nil {
				slog.Warn("failed to write skip detail file", "error", err)
			}
		}
	})
	return nil
}

// Register adds a ResourceEnumerator to the registry.
func (e *Enumerator) Register(l ResourceEnumerator) {
	e.enumerators[l.ResourceType()] = l
}

// List routes an identifier (ARN or resource type) to the appropriate enumerator.
// This has the same signature as CloudControlEnumerator.List for drop-in replacement.
// Skippable errors (access denied, unsupported type, region unavailable) are
// recorded in the SkipReport and swallowed so the pipeline continues. Non-skippable
// errors propagate so the caller sees real failures.
//
// This is the dispatcher-level safety net: inner-loop handling inside each
// enumerator provides per-region granularity, but any skippable error that
// escapes is still caught here.
func (e *Enumerator) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		if err := e.listByARN(parsed, identifier, out); err != nil {
			return e.handleListError(err, parsed.Service, "GetResource", parsed.Region)
		}
		return nil
	}

	if strings.HasPrefix(identifier, "AWS::") {
		if err := e.listByType(identifier, out); err != nil {
			service := identifier
			if parts := strings.Split(identifier, "::"); len(parts) >= 2 {
				service = strings.ToLower(parts[1])
			}
			return e.handleListError(err, service, "List", "")
		}
		return nil
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

// handleListError is the dispatcher-level safety net. It classifies err:
// skippable errors are recorded and nil is returned so the pipeline
// continues; everything else is returned as-is. Enumerators should handle
// errors internally for better skip report specificity — this catches
// anything that leaks.
func (e *Enumerator) handleListError(err error, service, operation, region string) error {
	if op := ClassifySkippable(err, service, operation, region); op != nil {
		slog.Debug("safety net caught leaked skippable error",
			"service", service, "operation", operation, "region", region, "code", op.ErrorCode)
		e.Skipped.Record(*op)
		return nil
	}
	return err
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
