package enumeration

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// translateFn produces a CloudControl GetResource identifier from a Config
// ResourceIdentifier. Returns ("", false) when no usable identifier can be
// derived, in which case the caller should skip the record without attempting
// a CloudControl GET.
type translateFn func(rec configtypes.ResourceIdentifier, accountID, region string) (string, bool)

// configIdentifier translates Config ResourceIdentifier records into the
// identifier format CloudControl GetResource expects for each resource type.
// Default behavior is a heuristic (ResourceName if non-empty, else ResourceId);
// per-type overrides handle the cases where the heuristic is wrong.
type configIdentifier struct {
	overrides map[string]translateFn
}

// newConfigIdentifier returns a configIdentifier pre-loaded with the
// per-type override table.
func newConfigIdentifier() *configIdentifier {
	return &configIdentifier{
		overrides: map[string]translateFn{
			// CloudFormation stores ResourceId as the stack ARN and ResourceName
			// as the stack name; CloudControl wants the name.
			"AWS::CloudFormation::Stack": returnResourceName,
			// Amplify stores ResourceId as AppId (d1xxx) and ResourceName as the
			// human-readable app name; CloudControl wants AppId.
			"AWS::Amplify::App": returnResourceID,
		},
	}
}

// Translate returns the CloudControl primary identifier for rec, along with a
// boolean indicating whether a usable identifier was derived.
func (t *configIdentifier) Translate(
	resourceType string,
	rec configtypes.ResourceIdentifier,
	accountID, region string,
) (string, bool) {
	if fn, ok := t.overrides[resourceType]; ok {
		return fn(rec, accountID, region)
	}
	return heuristicTranslate(rec)
}

// heuristicTranslate returns the identifier field that most Config-to-CloudControl
// translations need: ResourceName if populated, otherwise ResourceId. Returns
// ("", false) when neither field is set.
func heuristicTranslate(rec configtypes.ResourceIdentifier) (string, bool) {
	if name := aws.ToString(rec.ResourceName); name != "" {
		return name, true
	}
	if id := aws.ToString(rec.ResourceId); id != "" {
		return id, true
	}
	return "", false
}

func returnResourceName(rec configtypes.ResourceIdentifier, _, _ string) (string, bool) {
	name := aws.ToString(rec.ResourceName)
	if name == "" {
		return "", false
	}
	return name, true
}

func returnResourceID(rec configtypes.ResourceIdentifier, _, _ string) (string, bool) {
	id := aws.ToString(rec.ResourceId)
	if id == "" {
		return "", false
	}
	return id, true
}
