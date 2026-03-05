package enumeration

import (
	"errors"
	"fmt"
	"strings"

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
	listers map[string]ResourceEnumerator
	cc      *CloudControlEnumerator
}

// NewEnumerator creates an Enumerator with CloudControl fallback and registers
// all built-in resource-specific listers.
func NewEnumerator(opts plugin.AWSCommonRecon) *Enumerator {
	provider := NewAWSConfigProvider(opts)
	cc := NewCloudControlEnumeratorWithProvider(opts, provider)
	e := &Enumerator{
		listers: make(map[string]ResourceEnumerator),
		cc:      cc,
	}
	// Register built-in listers here as they are implemented.
	e.Register(NewS3Enumerator(opts, provider))
	return e
}

// Register adds a ResourceEnumerator to the registry.
func (e *Enumerator) Register(l ResourceEnumerator) {
	e.listers[l.ResourceType()] = l
}

// List routes an identifier (ARN or resource type) to the appropriate lister.
// This has the same signature as CloudControlEnumerator.List for drop-in replacement.
func (e *Enumerator) List(identifier string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsaarn.Parse(identifier)
	if err == nil {
		return e.listByARN(parsed, identifier, out)
	}

	if strings.HasPrefix(identifier, "AWS::") {
		return e.listByType(identifier, out)
	}

	return fmt.Errorf("identifier must be either an ARN or CloudControl resource type: %q", identifier)
}

func (e *Enumerator) listByARN(parsed awsaarn.ARN, rawARN string, out *pipeline.P[output.AWSResource]) error {
	resourceType, ok := types.ResolveResourceType(parsed.Service, parsed.Resource)
	if !ok {
		return e.cc.EnumerateByARN(rawARN, out)
	}

	if lister, ok := e.listers[resourceType]; ok {
		err := lister.EnumerateByARN(rawARN, out)
		if errors.Is(err, errFallbackToCloudControl) {
			return e.cc.EnumerateByARN(rawARN, out)
		}
		return err
	}

	return e.cc.EnumerateByARN(rawARN, out)
}

func (e *Enumerator) listByType(resourceType string, out *pipeline.P[output.AWSResource]) error {
	if lister, ok := e.listers[resourceType]; ok {
		return lister.EnumerateAll(out)
	}

	return e.cc.EnumerateByType(resourceType, out)
}
