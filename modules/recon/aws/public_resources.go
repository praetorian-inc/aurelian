package recon

import (
	"strconv"
	"time"

	"github.com/praetorian-inc/nebula/internal/logs"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/stages"
	"github.com/praetorian-inc/nebula/pkg/types"
)

var AwsPublicResourcesOptions = []*types.Option{
	&options.AwsRegionsOpt,
	&options.AwsResourceTypeOpt,
	types.SetDefaultValue(
		*types.SetRequired(
			options.FileNameOpt, false),
		AwsPublicResourcesMetadata.Id+"-"+strconv.FormatInt(time.Now().Unix(), 10)+".json"),
}

var AwsPublicResourcesOutputProviders = []func(options []*types.Option) types.OutputProvider{
	// op.NewConsoleProvider,
	op.NewJsonFileProvider,
}

var AwsPublicResourcesMetadata = modules.Metadata{
	Id:          "public-resources", // this will be the CLI command name
	Name:        "Public Resources",
	Description: "Return a list of public resources in an AWS account.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References:  []string{},
}

func NewAwsPublicResources(opts []*types.Option) (<-chan string, stages.Stage[string, []map[string]interface{}], error) {

	pipeline, err := stages.ChainStages[string, []map[string]interface{}](
		stages.Echo[string],
		stages.AwsPublicResources,
		stages.UnmarshalOutput,
		stages.AggregateOutput[map[string]interface{}],
	)

	if err != nil {
		return nil, nil, err
	}

	rtype := types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value

	if rtype == "ALL" {
		logs.ConsoleLogger().Info("Loading public resources recon module for all types")
		return stages.Generator(PublicTypes), pipeline, nil
	} else {
		logs.ConsoleLogger().Info("Loading public resources recon module for types: " + rtype)
		in := stages.ParseTypes(types.GetOptionByName(options.AwsResourceTypeOpt.Name, opts).Value)
		return in, pipeline, nil
	}
}

var PublicTypes = []string{
	"AWS::Backup::BackupVault",
	"AWS::Cognito::UserPool",
	"AWS::EBS::Snapshot",
	"AWS::EC2::FPGAImage",
	"AWS::EC2::Image",
	"AWS::EC2::Instance",
	"AWS::ECR::Repository",
	"AWS::ECR::PublicRepository",
	"AWS::EFS::FileSystem",
	"AWS::ElasticSearch::Domain",
	"AWS::Events::EventBus",
	"AWS::Glacier::Vault",
	"AWS::Glue::ResourcePolicy",
	"AWS::IAM::Role",
	"AWS::KMS::Key",
	"AWS::Lambda::Function",
	"AWS::Lambda::LayerVersion",
	"AWS::Logs::Destination",
	"AWS::Logs::ResourcePolicy",
	"AWS::MediaStore::Container",
	"AWS::OpenSearchService::Domain",
	"AWS::RDS::DBClusterSnapshot",
	"AWS::RDS::DBSnapshot",
	"AWS::S3::Bucket",
	"AWS::SecretsManager::Secret",
	"AWS::ServerlessRepo::Application",
	"AWS::SES::EmailIdentity",
	"AWS::SNS::Topic",
	"AWS::SQS::Queue",
}
