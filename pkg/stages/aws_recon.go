package stages

import (
	"context"
	"fmt"
	"sync"

	// AWS service imports

	// Legacy AWS SDK import needed for some helper functions

	// Internal imports

	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func AwsPublicResources(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "AwsPublicResources")
	out := make(chan string)

	go func() {
		defer close(out)
		for rtype := range in {

			logger.Debug("Running recon for resource type: " + rtype)
			var pl Stage[string, string]
			var err error
			switch rtype {
			case "AWS::Backup::BackupVault":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsBackupVaultCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .BackupVaultName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Cognito::UserPool":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsCognitoUserPoolGetDomains,
					AwsCognitoUserPoolDescribeClients,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"Domains\")) | {Type: .TypeName, Identifier: .Identifier, Domains: (.Properties | fromjson | .Domains), ClientProperties: (.Properties | fromjson | .ClientProperties // null)}"),
					ToString[[]byte],
				)

			case "AWS::EBS::Snapshot":
				pl, err = ChainStages[string, string](
					AwsEBSListSnapshots,
					AwsEbsSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::FPGAImage":
				pl, err = ChainStages[string, string](
					AwsEc2ListFPGAImages,
					AwsEc2FPGAImageDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"LoadPermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, LoadPermissions: (.Properties | fromjson | .LoadPermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::Image":
				pl, err = ChainStages[string, string](
					AwsEc2ListImages,
					AwsEc2ImageDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"LaunchPermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, LaunchPermissions: (.Properties | fromjson | .LaunchPermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::Instance":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"PublicIp\")) | {Identifier: .TypeName, Identifier: .Identifier, PublicIp: (.Properties | fromjson | .PublicIp)}"),
					ToString[[]byte],
				)

			case "AWS::ECR::Repository":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsEcrCheckRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .RepositoryName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ECR::PublicRepository":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsEcrCheckPublicRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "{Type: .TypeName, Identifier: (.Properties | fromjson | .RepositoryName), VulnerableAccessPolicies: \"all users can pull by default\", AdditionalVulnerablePermissions: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::EFS::FileSystem":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsEfsFileSystemCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .FileSystemId), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ElasticSearch::Domain":
				pl, err = ChainStages[string, string](
					AwsEsListDomains,
					AwsEsDomainCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DomainName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Events::EventBus":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsEventBusCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Name), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Glacier::Vault":
				pl, err = ChainStages[string, string](
					AwsGlacierListVaults,
					AwsGlacierVaultCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .VaultName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Glue::ResourcePolicy":
				pl, err = ChainStages[string, string](
					AwsGlueCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Arn), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::IAM::Role":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsIamRoleCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .RoleName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::KMS::Key":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsKmsKeyCheckResourcePolicy,
					AwsKmsKeyCheckGrants,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null) or (has(\"Grantees\") and $input.Grantees != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .KeyId), VulnerableGrantees: (.Properties | fromjson | .Grantees // null), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Lambda::Function":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsLambdaCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .FunctionName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Lambda::LayerVersion":
				pl, err = ChainStages[string, string](
					AwsLambdaListLayers,
					AwsLambdaLayerCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .LayerName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Logs::Destination":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsCloudControlGetResource,
					AwsCloudWatchDestinationCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DestinationName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			// this is an untested resource type
			case "AWS::Logs::ResourcePolicy":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsCloudControlGetResource,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"PolicyDocument\") and $input.PolicyDocument != null)) | {Type: .TypeName, VulnerableAccessPolicies: (.Properties | fromjson | .PolicyDocument // null)}"),
					ToString[[]byte],
				)

			case "AWS::MediaStore::Container":
				pl, err = ChainStages[string, string](
					AwsMediaStoreListContainers,
					AwsMediaStoreContainerCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Name), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::OpenSearchService::Domain":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsOpenSearchDomainCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DomainName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::RDS::DBClusterSnapshot":
				pl, err = ChainStages[string, string](
					AwsRdsListDbClusterSnapshots,
					AwsRdsDbClusterSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::RDS::DBSnapshot":
				pl, err = ChainStages[string, string](
					AwsRdsListDBSnapshots,
					AwsRdsDbSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::S3::Bucket":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsS3FixResourceRegion,
					AwsS3CheckBucketACL,
					AwsS3CheckBucketPolicy,
					AwsS3CheckBucketPAB,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | ((has(\"BucketACL\") and $input.BucketACL != null) or (has(\"AccessPolicy\") and $input.AccessPolicy != null))) | {Type: .TypeName, Identifier: (.Properties | fromjson | .BucketName), VulnerableBucketACLs: (.Properties | fromjson | .BucketACL // null), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SecretsManager::Secret":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsSecretCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Id), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ServerlessRepo::Application":
				pl, err = ChainStages[string, string](
					AwsServerlessApplicationsRepositoryList,
					AwsServerlessApplicationRepositoryCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .ApplicationId), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SES::EmailIdentity":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsSesIdentityCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .EmailIdentity), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SNS::Topic":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsSnsTopicCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .TopicArn), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SQS::Queue":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					AwsSqsQueueCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .QueueUrl), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)
			case "AWS::RDS::DBInstance":
				pl, err = ChainStages[string, string](
					AwsCloudControlListResources,
					Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(ctx, "select(.Properties | fromjson | .PubliclyAccessible == true) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DBInstanceArn), Endpoint: (.Properties | fromjson | .Endpoint.Address) + \":\" + (.Properties | fromjson | .Endpoint.Port)}"),
					ToString[[]byte],
				)

			default:
				continue
			}

			if err != nil {
				logger.Error("Failed to " + rtype + " create pipeline: " + err.Error())
				continue
			}

			wg := new(sync.WaitGroup)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range pl(ctx, opts, Generator([]string{rtype})) {
					out <- s
				}
			}()
			wg.Wait()
		}

	}()

	return out

}

func AwsFindSecretsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AwsFindSecretsStage")
	out := make(chan types.NpInput)
	go func() {
		defer close(out)

		for rtype := range in {
			message.Info("Searching %s for secrets", rtype)
			var pl Stage[string, types.NpInput]
			var err error

			switch rtype {
			case "AWS::Lambda::Function":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					EnrichedResourceDescriptionToNpInput,
				)
			case "AWS::Lambda::Function::Code":
				// we need to use the actual CC type
				rtype = "AWS::Lambda::Function"
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsLambdaGetCodeContent,
				)
			case "AWS::EC2::Instance":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsEc2GetUserDataStage,
				)
			case "AWS::CloudFormation::Stack":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsCloudFormationGetTemplatesNpInputStage,
				)
			case "AWS::ECR::Repository":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsEcrListImages,
					AwsEcrLoginStage,
					DockerPullStage,
					DockerSaveStage,
					DockerExtractToNPStage,
				)
			case "AWS::ECR::PublicRepository":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsEcrPublicListLatestImages,
					AwsEcrPublicLoginStage,
					DockerPullStage,
					DockerSaveStage,
					DockerExtractToNPStage,
				)
			case "AWS::ECS::TaskDefinition":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					EnrichedResourceDescriptionToNpInput,
				)
			case "AWS::SSM::Parameter":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsSsmListParameters,
					EnrichedResourceDescriptionToNpInput,
				)

			case "AWS::SSM::Document":
				pl, err = ChainStages[string, types.NpInput](
					// AwsCloudControlListResources can't be used as there's no way to filter on only user-created documents
					AwsSsmListDocuments,
					EnrichedResourceDescriptionToNpInput,
				)
			case "AWS::StepFunctions::StateMachine":
				pl, err = ChainStages[string, types.NpInput](
					AwsCloudControlListResources,
					AwsStepFunctionsListExecutionsStage,
					AwsStepFunctionsGetExecutionDetailsStage,
					AwsStateMachineExecutionDetailsToNpInputStage,
				)
			case "ALL":
				continue
			default:
				logger.Error("Unknown resource type: " + rtype)
				continue
			}

			logger.Info(fmt.Sprintf("Processing resource type %s", rtype))
			if err != nil {
				logger.Error("Failed to " + rtype + " create pipeline: " + err.Error())
				continue
			}

			for s := range pl(ctx, opts, Generator([]string{rtype})) {
				out <- s
			}
		}
	}()

	return out
}
