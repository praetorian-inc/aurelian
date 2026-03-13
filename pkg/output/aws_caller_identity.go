package output

import "github.com/praetorian-inc/aurelian/pkg/model"

// CallerIdentity represents the AWS identity of the current caller,
// extracted covertly from API error messages that leak the caller ARN.
type CallerIdentity struct {
	model.BaseAurelianModel

	// Status is "success" if an ARN was extracted, or "no_arn_found" if all
	// API calls succeeded (meaning the caller has permissions and no error
	// message was returned to extract from).
	Status string `json:"status"`

	// ARN is the full ARN of the caller, extracted from an API error message.
	// Examples:
	//   "arn:aws:iam::123456789012:user/alice"
	//   "arn:aws:sts::123456789012:assumed-role/role-name/session-name"
	ARN string `json:"arn,omitempty"`

	// Account is the AWS account ID parsed from the ARN (e.g., "123456789012")
	Account string `json:"account,omitempty"`

	// Method is the technique that successfully extracted the ARN
	// (e.g., "timestream", "pinpoint", "sqs")
	Method string `json:"method,omitempty"`
}
