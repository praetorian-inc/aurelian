package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/docker"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ecr"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var ECRDump = chain.NewModule(
	cfg.NewMetadata(
		"ECR Dump",
		"Dump ECR container filesystems to disk and optionally scan for secrets using NoseyParker.",
	).WithProperties(map[string]any{
		"id":          "ecr-dump",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	// First get the resource types for ECR repositories
	general.NewResourceTypePreprocessor(&AWSECRResourceTypes{}),
	// List ECR resources using CloudControl
	cloudcontrol.NewAWSCloudControl,
	// List images for both private and public repositories
	ecr.NewAWSECRListImages,
	ecr.NewAWSECRListPublicImages,
	// Authenticate for both private and public repositories
	ecr.NewAWSECRLogin,
	ecr.NewAWSECRLoginPublic,
	// Pull the Docker images
	docker.NewDockerPull,
	// Save images to local tar files
	docker.NewDockerSave,
	// Extract to filesystem
	docker.NewDockerExtractToFS,
	// Convert to NoseyParker inputs and scan
	docker.NewDockerExtractToNP,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, 
		cfg.WithArg("continue_piping", true)),
).WithInputParam(
	options.AwsResourceType().WithDefault([]string{"AWS::ECR::Repository", "AWS::ECR::PublicRepository"}),
).WithConfigs(
	cfg.WithArg("extract", "true"),
	cfg.WithArg("noseyparker-scan", "true"),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithAutoRun()

// AWSECRResourceTypes implements the SupportsResourceTypes interface
type AWSECRResourceTypes struct{}

func (a *AWSECRResourceTypes) SupportedResourceTypes() []string {
	return []string{
		"AWS::ECR::Repository",
		"AWS::ECR::PublicRepository",
	}
}

func init() {
	registry.Register("aws", "recon", "ecr-dump", *ECRDump)
}