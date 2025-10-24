package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/llm"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

func init() {
	registry.Register("aws", "recon", AWSScreenshotAnalysis.Metadata().Properties()["id"].(string), *AWSScreenshotAnalysis)
}

var AWSScreenshotAnalysis = chain.NewModule(
	cfg.NewMetadata(
		"AWS EC2 Screenshot Analysis",
		"Capture EC2 console screenshots and analyze them for sensitive information using Claude AI",
	).WithProperties(map[string]any{
		"id":          "ec2-screenshot-analysis",
		"platform":    "aws",
		"opsec_level": "low", // Only captures screenshots, no intrusive operations
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsResourceType().Name(),
	),
).WithLinks(
	// Resource type preprocessing to filter for EC2 instances
	general.NewResourceTypePreprocessor(AWSScreenshotAnalysisInstance),

	// Discover EC2 instances using CloudControl
	cloudcontrol.NewAWSCloudControl,

	// Capture console screenshots
	ec2.NewAWSEC2ScreenshotCapture,

	// Analyze screenshots with Claude AI (optional - continues if no API key)
	llm.NewAnthropicLLMAnalyzer,
).WithOutputters(
	// Write screenshot files and display analysis results
	outputters.NewScreenshotOutputter,

	// JSON output for programmatic consumption
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	// Resource type selection (defaults to EC2 instances)
	options.AwsResourceType().WithDefault([]string{"AWS::EC2::Instance"}),
).WithInputParam(
	// AWS profile selection
	options.AwsProfile(),
).WithParams(
	// Module name for file naming
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),

	// Anthropic API configuration
	cfg.NewParam[string]("anthropic-api-key", "Anthropic API key for Claude analysis (optional)").WithDefault(""),
	cfg.NewParam[string]("anthropic-model", "Claude model to use for analysis").WithDefault("claude-3-7-sonnet-latest"),
	cfg.NewParam[string]("analysis-prompt", "Custom analysis prompt (uses EC2-optimized default if not specified)").WithDefault(getDefaultEC2ScreenshotPrompt()),
	cfg.NewParam[int]("max-tokens", "Maximum tokens for Claude response").WithDefault(1000),
).WithConfigs(
	// Set module name for output file naming
	cfg.WithArg("module-name", "screenshot-analysis"),
).WithStrictness(
	// Use Lax strictness so the chain continues even if LLM analysis fails
	chain.Lax,
)

// AWSScreenshotAnalysis implements the resource type interface for preprocessing
type AWSScreenshotAnalysisProcessor struct{}

func (p *AWSScreenshotAnalysisProcessor) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.AWSEC2Instance,
	}
}

// Create an instance for the preprocessor
var AWSScreenshotAnalysisInstance = &AWSScreenshotAnalysisProcessor{}

// getDefaultEC2ScreenshotPrompt returns the default prompt optimized for EC2 console screenshot analysis
func getDefaultEC2ScreenshotPrompt() string {
	return `You are a security expert analyzing an AWS EC2 console screenshot for sensitive information exposure. This screenshot was automatically captured during a security assessment.

ANALYSIS FOCUS:
Examine this EC2 console screenshot for any sensitive information that should not be visible in production environments.

CRITICAL ITEMS TO DETECT:
1. **Credentials & Secrets**:
   - Passwords, passphrases, or authentication tokens visible on screen
   - AWS access keys, secret keys, or temporary credentials
   - API keys, tokens, or service account credentials
   - Database connection strings or authentication details
   - SSH private keys, certificates, or keypairs displayed in text
   - OAuth tokens, JWT tokens, or session identifiers

2. **AWS-Specific Information**:
   - EC2 instance metadata service (IMDS) responses containing sensitive data
   - User data scripts with embedded secrets or credentials
   - Environment variables containing AWS keys or database passwords
   - CloudFormation or Terraform output showing secrets
   - AWS CLI configuration files with credentials
   - IAM role assumption commands with sensitive parameters

3. **System & Application Data**:
   - Database hostnames, connection ports, schema names, or connection strings
   - Service endpoints, internal URLs, or system paths
   - Configuration files displaying credentials or sensitive parameters
   - Log files showing authentication details or system internals
   - Application console output containing API keys or tokens

   **Note**: Do not flag standard IP addresses, VPC CIDRs, or basic network information as sensitive unless they're part of connection strings or credential contexts.

4. **Infrastructure Secrets**:
   - Container registry credentials or deployment keys
   - CI/CD pipeline secrets, build tokens, or automation credentials
   - SSL/TLS certificates, private keys, or security credentials
   - Backup encryption keys or disaster recovery credentials
   - Third-party service integration keys or webhooks

5. **Personal & Business Data**:
   - Personal Identifiable Information (PII) in logs or application output
   - Financial information, payment details, or customer data
   - Internal employee information, contact details, or org charts
   - Business-sensitive data that should not be exposed

EC2-SPECIFIC SECURITY CONCERNS:
- Pay special attention to terminal windows showing AWS CLI commands
- Look for EC2 instance connect sessions with visible authentication
- Check for systems manager (SSM) session outputs containing credentials
- Examine any displayed user data or bootstrap scripts
- Review console logs that might contain sensitive startup information
- Look for Docker containers or applications displaying environment variables

RESPONSE FORMAT:
Respond with a JSON object containing:
{
  "sensitive_info_found": boolean,
  "confidence_score": float (0.0-1.0),
  "summary": "Brief description of findings or 'No sensitive information detected'",
  "findings": [
    {
      "type": "aws_credential|api_key|password|secret|pii|financial|infrastructure|system_info",
      "description": "Detailed description of what was found and why it's concerning",
      "confidence": float (0.0-1.0),
      "location": "Description of where in the screenshot it appears (top-left, terminal window, etc.)",
      "severity": "low|medium|high|critical"
    }
  ]
}

SEVERITY GUIDELINES:
- Critical: AWS root credentials, production database passwords, or widespread system access
- High: Service-specific API keys, database connections, or significant infrastructure access
- Medium: Development credentials, internal URLs, or limited-scope secrets
- Low: Non-sensitive system information or low-impact configuration details

If no sensitive information is detected, respond with "sensitive_info_found": false and provide a brief summary confirming the screenshot appears secure.`
}
