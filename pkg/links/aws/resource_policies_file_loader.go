package aws

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePoliciesFileLoader struct {
	*base.AwsReconLink
}

func NewAwsResourcePoliciesFileLoader(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePoliciesFileLoader{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (r *AwsResourcePoliciesFileLoader) Process(input any) error {
	resourcePoliciesFile, err := cfg.As[string](r.Arg("resource-policies-file"))
	if err != nil {
		return fmt.Errorf("resource-policies-file parameter is required: %w", err)
	}

	if resourcePoliciesFile == "" {
		return fmt.Errorf("resource-policies-file parameter cannot be empty")
	}

	// Read the resource policies file
	data, err := os.ReadFile(resourcePoliciesFile)
	if err != nil {
		return fmt.Errorf("failed to read resource policies file '%s': %w", resourcePoliciesFile, err)
	}

	// Parse the file as array first (in case it was output from resource-policies module in array format)
	var resourcePoliciesArray []map[string]*types.Policy
	if err := json.Unmarshal(data, &resourcePoliciesArray); err == nil && len(resourcePoliciesArray) > 0 {
		// Take the first element if it's in array format
		r.Send(outputters.NewNamedOutputData(resourcePoliciesArray[0], "resource-policies"))
		r.Logger.Info(fmt.Sprintf("Successfully loaded resource policies from %s (%d policies)", resourcePoliciesFile, len(resourcePoliciesArray[0])))
		return nil
	}

	// Parse as map[string]*types.Policy directly (expected format)
	var resourcePolicies map[string]*types.Policy
	if err := json.Unmarshal(data, &resourcePolicies); err != nil {
		return fmt.Errorf("failed to parse resource policies file '%s' as JSON (tried both array and map format): %w", resourcePoliciesFile, err)
	}

	// Validate that it's not empty
	if len(resourcePolicies) == 0 {
		r.Logger.Warn("Resource policies file contains no policies")
	}

	// Send the resource policies map
	r.Send(outputters.NewNamedOutputData(resourcePolicies, "resource-policies"))
	r.Logger.Info(fmt.Sprintf("Successfully loaded resource policies from %s (%d policies)", resourcePoliciesFile, len(resourcePolicies)))
	return nil
}
